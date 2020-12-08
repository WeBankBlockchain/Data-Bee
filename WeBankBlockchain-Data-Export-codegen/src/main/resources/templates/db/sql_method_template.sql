CREATE TABLE ${table_name} (
  	pk_id bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键id',
  	block_height bigint(20) NOT NULL COMMENT '交易所在块高',
  	tx_hash varchar(100) NOT NULL COMMENT '交易哈希',
	<%
	for(entry in list){
		var key = entry.sqlName;
        var value = entry.sqlType;
	%>
	${key} ${value} NOT NULL,
	<% } %>	
	<%
	for(entry in list){
		var key = entry.sqlName;
		var value = entry.sqlType;		
		if(strutil.contain(key,"id") || strutil.contain(key,"owner")){
			if(!strutil.contain(value,"ext")){
				println("	KEY `" + key + "` (`" + key + "`),");
			}
		}
	 }
	%>	
	<%
	for(entry in outputList){
		var key = entry.sqlName;
        var value = entry.sqlType;
	%>
	${key} ${value} NOT NULL,
	<% } %>		
  	`updatetime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
 	PRIMARY KEY (pk_id)
) COMMENT='${table_name}' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;