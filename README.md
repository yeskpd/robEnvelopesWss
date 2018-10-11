使用webSocket进入聊天室获取红包信息，控制账号抢红包。

# 文件说明
config.json # 是配置文件
receive_id.txt # 是抢购的记录ID文件
userList.txt # 是账号默认文件 格式（网址----账号----密码）
领取记录.txt # 只记录抢购的包数据
logs.txt # 日志文件

# 项目包，无法保证是否全部已导出，按照错误百度找所需包。

# 配置说明
{
  "debug":false, # 是否调试输出
  "threadNum":10, # 线程大小
  "heartbeatTime":30, # 心跳间隔/秒
  "loginErrTime":60, # 登录失败间隔多久尝试
  "loadTextUserPath":"./userList.txt" # 账号路径  格式（网址----账号----密码）
}