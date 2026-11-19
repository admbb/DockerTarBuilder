package storage

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net/netip"
	"time"

	"netflow-plus-v2/internal/flow"
)

const sequenceCycle int64 = 1 << 32
const reorderRecords int64 = 65536
const reorderSeconds uint32 = 30

// IPFIXPacket supplies the wire record count, including records filtered from
// the accounting view, and the evidence needed to validate the boot.
type IPFIXPacket struct {
	Domain, Sequence, RecordCount uint32
	ExportTime, TemplateTime      uint32
	BootMS                        uint64
	TemplateChanged               bool
}

func (s *Store) SaveIPFIXPacket(ctx context.Context, exporter netip.Addr, digest [32]byte, received time.Time, flows []flow.Flow, packet IPFIXPacket) (bool, error) {
	return s.saveFlowMessage(ctx, exporter, digest, received, flows, packet.Domain, packet.Sequence, packet.RecordCount, &packet)
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func flowMessageSeen(ctx context.Context, q queryRower, exporter, digest string) (bool, error) {
	var exists int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM flow_messages WHERE exporter=? AND digest=?
		UNION ALL SELECT 1 FROM ipfix_ranges WHERE exporter=? AND digest=?
		UNION ALL SELECT 1 FROM flow_sequences WHERE exporter=? AND digest=? LIMIT 1`,
		exporter, digest, exporter, digest, exporter, digest).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

type ipfixSession struct {
	bootMS               uint64
	exportTime, wrapTime uint32
	nextSeq              int64
	legacy               bool
}

func recordIPFIXSequence(ctx context.Context, tx *sql.Tx, exporter, digest string, p IPFIXPacket) (bool, error) {
	seen, err := flowMessageSeen(ctx, tx, exporter, digest)
	if err != nil || seen {
		return seen, err
	}
	var session ipfixSession
	err = tx.QueryRowContext(ctx, `SELECT boot_ms,export_time,next_seq,wrap_time,legacy FROM ipfix_sessions WHERE exporter=? AND domain=?`,
		exporter, p.Domain).Scan(&session.bootMS, &session.exportTime, &session.nextSeq, &session.wrapTime, &session.legacy)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	exportEnd := uint64(p.ExportTime)*1000 + 999
	if p.RecordCount == 0 {
		if p.TemplateChanged || (exists && exportEnd < session.bootMS) {
			return false, errors.New("IPFIX template change or retired boot is unverified")
		}
		return false, nil
	}
	if p.BootMS == 0 || p.BootMS > exportEnd {
		return false, errors.New("IPFIX data has no consistent exporter boot time")
	}
	if p.TemplateTime == 0 || uint64(p.TemplateTime)*1000+999 < p.BootMS {
		return false, errors.New("IPFIX exporter boot needs refreshed templates")
	}
	newBoot := !exists || session.bootMS != p.BootMS
	start := int64(p.Sequence)
	if newBoot {
		if exists && (p.BootMS <= uint64(session.exportTime)*1000+999 ||
			int64(p.Sequence) > reorderRecords || int64(p.Sequence) >= session.nextSeq) {
			return false, errors.New("IPFIX exporter reboot lacks a later boot time and a low reset sequence")
		}
		session = ipfixSession{bootMS: p.BootMS}
		if !exists {
			// Old databases do not identify the boot that generated their
			// modulo ranges. Keep honoring those ranges for the first boot.
			err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM flow_sequences WHERE exporter=? AND observation_domain=?)`,
				exporter, p.Domain).Scan(&session.legacy)
			if err != nil {
				return false, err
			}
		}
	} else {
		if p.TemplateChanged {
			return false, errors.New("IPFIX template changed within the same boot")
		}
		start, err = session.logicalStart(p)
		if err != nil {
			return false, err
		}
	}
	end := start + int64(p.RecordCount)
	if session.legacy {
		ok, err := overlapsLegacySequence(ctx, tx, exporter, p)
		if err != nil {
			return false, err
		}
		if ok {
			return false, errors.New("IPFIX sequence overlaps data from the previous collector version")
		}
	}
	var overlaps bool
	err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT end_seq>? FROM ipfix_ranges WHERE exporter=? AND domain=? AND boot_ms=?
		AND start_seq<? ORDER BY start_seq DESC LIMIT 1),0)`, start, exporter, p.Domain, p.BootMS, end).Scan(&overlaps)
	if err != nil {
		return false, err
	}
	if overlaps {
		return false, errors.New("overlapping IPFIX sequence range")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ipfix_ranges(exporter,domain,boot_ms,start_seq,end_seq,digest) VALUES(?,?,?,?,?,?)`,
		exporter, p.Domain, p.BootMS, start, end, digest); err != nil {
		return false, err
	}
	if end/sequenceCycle > session.nextSeq/sequenceCycle {
		session.wrapTime = p.ExportTime
	}
	session.nextSeq = max(session.nextSeq, end)
	session.exportTime = max(session.exportTime, p.ExportTime)
	_, err = tx.ExecContext(ctx, `INSERT INTO ipfix_sessions(exporter,domain,boot_ms,export_time,next_seq,wrap_time,legacy) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(exporter,domain) DO UPDATE SET boot_ms=excluded.boot_ms,export_time=excluded.export_time,
		next_seq=excluded.next_seq,wrap_time=excluded.wrap_time,legacy=excluded.legacy`,
		exporter, p.Domain, p.BootMS, session.exportTime, session.nextSeq, session.wrapTime, session.legacy)
	return false, err
}

func (s ipfixSession) logicalStart(p IPFIXPacket) (int64, error) {
	delta := int64(int32(p.Sequence - uint32(s.nextSeq)))
	if s.nextSeq > math.MaxInt64-int64(p.RecordCount)-max(delta, 0) {
		return 0, errors.New("IPFIX logical sequence overflow")
	}
	start := s.nextSeq + delta
	if start < 0 || delta < -reorderRecords || uint64(p.ExportTime)+uint64(reorderSeconds) < uint64(s.exportTime) {
		return 0, errors.New("IPFIX data is outside the reordering window")
	}
	end := start + int64(p.RecordCount)
	if end/sequenceCycle > s.nextSeq/sequenceCycle && (delta > reorderRecords || p.ExportTime < s.exportTime) {
		return 0, errors.New("IPFIX sequence wrap is unverified")
	}
	if s.wrapTime > 0 && start/sequenceCycle == s.nextSeq/sequenceCycle && p.ExportTime < s.wrapTime {
		return 0, errors.New("IPFIX export time predates the sequence wrap")
	}
	if delta >= 0 && p.ExportTime < s.exportTime {
		return 0, errors.New("IPFIX forward sequence has an older export time")
	}
	return start, nil
}

func overlapsLegacySequence(ctx context.Context, tx *sql.Tx, exporter string, p IPFIXPacket) (bool, error) {
	start, end := int64(p.Sequence), int64(p.Sequence)+int64(p.RecordCount)
	ranges := [][2]int64{{start, min(end, sequenceCycle)}}
	if end > sequenceCycle {
		ranges = append(ranges, [2]int64{0, end - sequenceCycle})
	}
	for _, bounds := range ranges {
		var overlaps bool
		err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT end_seq>? FROM flow_sequence_ranges
			WHERE exporter=? AND observation_domain=? AND start_seq<? ORDER BY start_seq DESC LIMIT 1),0)`,
			bounds[0], exporter, p.Domain, bounds[1]).Scan(&overlaps)
		if err != nil || overlaps {
			return overlaps, err
		}
	}
	return false, nil
}
