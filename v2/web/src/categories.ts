const names:Record<string,string>={video:"视频娱乐",music:"音乐",social:"社交通讯",gaming:"游戏",ai:"人工智能",developer:"开发",system:"系统服务",cloud:"云服务",office:"办公",shopping:"电商",download:"文件下载"};
export const categoryName=(key:string)=>Object.prototype.hasOwnProperty.call(names,key)?names[key]:key;
