#!/usr/bin/env bash
LANG=zh_CN.UTF-8

##############################################################################
##
##  WeBankBlockchain-Data-Export start up script for UN*X.
##  WeBankBlockchain-Data-Export is an automatic code Generator.
##
##  created by jiayumao
##
##############################################################################

# project info
SETTING_PATH=~/.data_export
PROJECT_NAME="WeBankBlockchain-Data-Export"
CODEGEN="${PROJECT_NAME}-codegen"
COMMON="${PROJECT_NAME}-common"
CORE="${PROJECT_NAME}-core"
DB="${PROJECT_NAME}-db"
BASE_DIR=`pwd`

# functions
function prop {
    grep "${1}" application.properties|cut -d'=' -f2
}

function is_empty_dir(){ 
    ls -A $1|wc -w
}

function LOG_ERROR()
{
    local content=${1}
    echo -e "\033[31m"${content}"\033[0m"
}

# @function: output information log
# @param: content: information message
function LOG_INFO()
{
    local content=${1}
    echo -e "\033[32m"${content}"\033[0m"
}

function check_java(){
   version=$($JAVACMD -version 2>&1 |grep version |awk '{print $3}')
   len=${#version}-2
   version=${version:1:len}

   IFS='.' arr=($version)
   IFS=' '
   if [ -z ${arr[0]} ];then
      LOG_ERROR "At least Java8 is required."
      exit 1
   fi
   if [ ${arr[0]} -eq 1 ];then
      if [ ${arr[1]} -lt 8 ];then
           LOG_ERROR "At least Java8 is required."
           exit 1
      fi
   elif [ ${arr[0]} -gt 8 ];then
          :
   else
       LOG_ERROR "At least Java8 is required."
       exit 1
   fi
}

function checkout_version(){
  CONFIG_BAK_PATH=${SETTING_PATH}/config
  CONFIG_BAK_NAME=${SETTING_PATH}/config`date +%s`
  if [ ! -d $SETTING_PATH ];then
    mkdir -p $SETTING_PATH
  fi
  if [ -d $CONFIG_BAK_PATH ];then
    mv $CONFIG_BAK_PATH $CONFIG_BAK_NAME
    LOG_INFO "move tools/config to backup path: ${CONFIG_BAK_NAME}"
  fi
  rm -rf $CODEGEN
  rm -rf $COMMON
  mv tools/config $SETTING_PATH
  git reset --hard HEAD
  if [ ${ver} != "latest" ]; then
    if [ $(git tag -l "V$ver") ]; then
      git checkout V$ver
    else
      LOG_ERROR "Export version $ver is not exists, please check."
      exit 1;
    fi
  fi
  rm -rf tools/config
  cp -rf $CONFIG_BAK_PATH tools/
}

function generate_group(){
	APPLICATION_I="$BASE_DIR/$BUILD_DIR/config/application-$1.properties"
	APPLICATION_DB_I="$BASE_DIR/$BUILD_DIR/config/application-sharding-tables-$1.properties"
	cp $BASE_DIR/$BUILD_DIR/config/application.properties $APPLICATION_I
	cp $BASE_DIR/$BUILD_DIR/config/application-sharding-tables.properties $APPLICATION_DB_I
	DB_NAME_TMP="${system_dbUrl%%\?*}"
	DB_NAME="${DB_NAME_TMP##*/}"
	NEW_DB_NAME="${DB_NAME}_g$1"
	LOG_INFO "new db name is $NEW_DB_NAME"
	GID=`cat $APPLICATION_I | grep -n "system.groupId" | cut -d ":" -f 2`
	if [ "$(uname)" == "Darwin" ]; then
      sed -i "" "s/${GID}/system.groupId=$1/g" $APPLICATION_I
      sed -i "" "s/${server_port}/$2/g" $APPLICATION_I
      sed -i "" "s/dataexport-core.log/dataexport-core-g${1}.log/g" $APPLICATION_I
      sed -i "" "s/${DB_NAME}/$NEW_DB_NAME/g" $APPLICATION_DB_I
    elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
      sed -i "s/${GID}/system.groupId=$1/g" $APPLICATION_I
      sed -i "s/${server_port}/$2/g" $APPLICATION_I
      sed -i "s/dataexport-core.log/dataexport-core-g${1}.log/g" $APPLICATION_I
      sed -i "s/${DB_NAME}/$NEW_DB_NAME/g" $APPLICATION_DB_I
    fi
    cd $BASE_DIR/$BUILD_DIR
    echo "nohup java -jar `pwd`/*.jar >/dev/null 2>&1 --spring.profiles.active=$1,sharding-tables-$1 & " >> start_all_groups.sh
}

function generate_groups(){ 
	cd $BASE_DIR/$BUILD_DIR
	touch start_all_groups.sh
	echo "#!/usr/bin/env bash " >> start_all_groups.sh
	IFS=',' read -r -a groupIdArrary <<< "$system_groupId"
	for ((i=0; i<${#groupIdArrary[@]}; i++))
	do
    	groupId=${groupIdArrary[$i]}
    	port=`expr ${server_port} + ${i}`    
    	cd $BASE_DIR
    	LOG_INFO "Begin to generate group ${groupId} ${port}"
    	generate_group $groupId $port    
	done
}

### get argvs
ver="latest"
exec="run"
GRADLE_EXEC="bash gradlew "
while getopts "e:v:c:" arg
do
  case $arg in
    e)
      execArg=$(echo "$OPTARG" | tr '[:upper:]' '[:lower:]')
      if [ "$execArg" != "run" ] && [ "$execArg" != "build" ]; then
        LOG_ERROR "-e execute mode: [build|run]"
      else
        exec=$execArg
      fi
      ;;
    v)
      ver=$OPTARG
      ;;
    c)
      execArg=$(echo "$OPTARG" | tr '[:upper:]' '[:lower:]')
      if [ "$execArg" != "gradle" ] && [ "$execArg" != "gradlew" ]; then
        LOG_ERROR "-c execute mode: [gradlew|gradle]"
      elif [ "$execArg" == "gradle" ]; then
        GRADLE_EXEC=$execArg
        LOG_INFO "Begin to use gradle"
      else
        LOG_INFO "Begin to use gradle wrapper"
      fi
      ;;
    ?)
      LOG_ERROR "unkonw argument\nusage: -e [build|run], -v [export_version], -c [gradle|gradlew]"
      exit 1
      ;;
  esac
done

LOG_INFO "work dir is $BASE_DIR"
LOG_INFO "execute mode = $exec"
LOG_INFO "export version = $ver"

#### config props
APPLICATION_FILE="config/resources/application.properties"
DEF_FILE="config/resources/*.def"
APPLICATION_TMP_FILE="config/resources/application.properties.tmp"
CONTRACT_DIR="config/contract"
CERT_DIR="config/resources"
RESOURCE_DIR="src/main/resources"
JAVA_CODE_DIR="src/main/java"
BUILD_DIR="dist"

#### system tables
ENTITY_DIR="$DB/src/main/java/com/webank/blockchain/data/export/db/entity"
BLOCK_DETAIL_INFO_TABLE="block_detail_info"
BLOCK_RAW_DATA_TABLE="block_raw_data"
BLOCK_TASK_POOL_TABLE="block_task_pool"
BLOCK_TX_DETAIL_INFO_TABLE="block_tx_detail_info"
CONTRACT_INFO_TABLE="contract_info"
DEPLOYED_ACCOUNT_INFO="deployed_account_info"
TX_RAW_DATA="tx_raw_data"
TX_RECEIPT_RAW_DATA="tx_receipt_raw_data"

#### check the config file exists.
if [ -f "$APPLICATION_FILE" ];then
  LOG_INFO "Check [appliction.properties] done."
else
  LOG_ERROR "The config file [appliction.properties] doesn't exist. Please don't delete it."
  exit 1
fi
if [ -d "$CONTRACT_DIR" ];then
  LOG_INFO "Check [contracts] done."
else
  LOG_ERROR "The config dir [contracts] doesn't exist. Please don't delete it."
  exit 1
fi
if [ "`ls -A $CONTRACT_DIR`" = "" ]; then
  LOG_ERROR "$CONTRACT_DIR is indeed empty"
  exit 1
fi
if [ -d "$CERT_DIR" ];then
  LOG_INFO "Check [resources] done."
else
  LOG_ERROR "The config dir [resources] doesn't exist. Please don't delete it."
  exit 1
fi
if [ "`ls -A $CERT_DIR`" = "" ]; then
  LOG_ERROR "$CERT_DIR is indeed empty"
  exit 1
fi

# Begin to read parameters from application.properties
if [ -f "$APPLICATION_FILE" ]
then
  LOG_INFO "$APPLICATION_FILE exist."
  grep -v "^#"  $APPLICATION_FILE | grep -v "^$" | grep "="  > $APPLICATION_TMP_FILE

  while IFS='=' read -r key value
  do
    key=$(echo $key | tr '.' '_')
    key=`echo $key |sed 's/^ *\| *$//g'`
    eval "${key}='${value}'"
  done < "$APPLICATION_TMP_FILE"
  rm -f $APPLICATION_TMP_FILE
else
  LOG_ERROR "$APPLICATION_FILE not found."
  exit 1
fi

LOG_INFO "system.nodeStr =  ${system_nodeStr} "
LOG_INFO "system.groupId          =  ${system_groupId} "
LOG_INFO "system.dbUrl =  ${system_dbUrl} "
LOG_INFO "system.dbUser =  ${system_dbUser} "
LOG_INFO "system.dbPassword =  ${system_dbPassword} "
LOG_INFO "system.group          =  ${system_group} "
LOG_INFO "system.baseProjectPath          =  ${system_baseProjectPath} "
LOG_INFO "system.contractPackName =  ${system_contractPackName} "
LOG_INFO "system.multiLiving = ${system_multiLiving} "
LOG_INFO "server.port             =  ${server_port} "
LOG_INFO "system.tablePrefix =  ${system_tablePrefix} "
LOG_INFO "system.tablePostfix =  ${system_tablePostfix} "


# begin to check config nt null
if  [ ! -n "${system_nodeStr}" ] ;then
LOG_ERROR "invalid system nodestr! Please check the application.properties."
exit 1
fi
if  [ ! -n "${system_groupId}" ] ;then
LOG_ERROR "invalid system groupId! Please check the application.properties."
exit 1
fi
if  [ ! -n "${system_dbUrl}" ] ;then
LOG_ERROR "invalid system dbUrl! Please check the application.properties."
exit 1
fi
if  [ ! -n "${system_dbUser}" ] ;then
LOG_ERROR "invalid system dbUser! Please check the application.properties."
exit 1
fi
if  [ ! -n "${system_dbPassword}" ] ;then
LOG_ERROR "invalid system dbPassword! Please check the application.properties."
exit 1
fi
if  [ ! -n "${system_group}" ] ;then
LOG_ERROR "invalid system group! Please check the application.properties."
exit 1
fi
if  [ ! -n "${system_baseProjectPath}" ] ;then
LOG_ERROR "invalid system baseProjectPath! Please check the application.properties."
exit 1
fi
if  [ ! -n "${system_contractPackName}" ] ;then
LOG_ERROR "invalid system contractPackName! Please check the application.properties."
exit 1
fi
if  [ ! -n "${system_multiLiving}" ] ;then
LOG_ERROR "invalid system multiLiving! Please check the application.properties."
exit 1
fi
if  [ ! -n "${server_port}" ] ;then
LOG_ERROR "invalid server port! Please check the application.properties."
exit 1
fi

count=`find $BASE_DIR/$CONTRACT_DIR -type f -print |grep ".java" | wc -l`
LOG_INFO "Find $count java files"
if [[ $count -lt 1 ]];then
  LOG_ERROR "Not find java files."
  exit 1
fi

## begin to check java package name
LOG_INFO "Checking your java contract package name ..."
for file in $BASE_DIR/$CONTRACT_DIR/*
do
  if head -n 1 $file | grep "${system_contractPackName}">/dev/null
  then
    continue
  else
    LOG_ERROR "Invalid java package name. Please make sure your config is equal to your package name."
    exit 1
  fi
done

# check the environment
## check server port is used
check_port() {
        LOG_INFO "Checking instance port ..."
        netstat -tlpn | grep "\b$1\b"
}
if check_port $server_port
then
        LOG_ERROR "ERROR: the port of server is used, please check it or modify server.port in application.properties."
    exit 1
fi

# Determine the Java command to use to start the JVM.
if [ -n "$JAVA_HOME" ] ; then
    if [ -x "$JAVA_HOME/jre/sh/java" ] ; then
        # IBM's JDK on AIX uses strange locations for the executables
        JAVACMD="$JAVA_HOME/jre/sh/java"
    else
        JAVACMD="$JAVA_HOME/bin/java"
    fi
    if [ ! -x "$JAVACMD" ] ; then
        die "ERROR: JAVA_HOME is set to an invalid directory: $JAVA_HOME
Please set the JAVA_HOME variable in your environment to match the
location of your Java installation."
    fi
else
    JAVACMD="java"
    which java >/dev/null 2>&1 || die "ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
Please set the JAVA_HOME variable in your environment to match the
location of your Java installation."
fi
LOG_INFO "JAVACMD: $JAVACMD"

## check the version of Java
check_java

contractPath=$(echo ${system_contractPackName} | tr '.' '/')
LOG_INFO "contractPath: $contractPath"
group=$(echo ${system_group} | tr '.' '/')
LOG_INFO "group: $group"

## for multiple groups
LOG_INFO "groupIds =  ${system_groupId} "
LOG_INFO "ports =  ${server_port} "


cd ..
checkout_version
if [ $? == 0 ];then
	LOG_INFO "git pull success"
else
	LOG_ERROR "git pull fail"
    exit 1;
fi

## rm cached files
cd $CODEGEN
rm -rf src/main/java/com/webank/blockchain/demo/
rm -rf src/main/java/org/

cd ..
## rm cached files
rm -rf src/main/java/com/webank/blockchain/data/export/generated
rm -rf src/main/java/com/webank/blockchain/data/export/generated
rm -rf src/main/java/com/webank/blockchain/demo
rm -rf src/main/java/org

# replace table name check
LOG_INFO "Replace table name check."
cd $BASE_DIR
# prefix/postfix not empty and not whitespace
if [ ! -z "${system_tablePrefix//[[:blank:]]/}" ] || [ ! -z "${system_tablePostfix//[[:blank:]]/}" ]; then
  prefix=${system_tablePrefix//[[:blank:]]}
  postfix=${system_tablePostfix//[[:blank:]]/}
  LOG_INFO "Replacing table name, tablePrefix=$prefix, tablePostfix=$postfix"
  NEW_BLOCK_DETAIL_INFO_TABLE="${BLOCK_DETAIL_INFO_TABLE}"
  NEW_BLOCK_RAW_DATA_TABLE="${BLOCK_RAW_DATA_TABLE}"
  NEW_BLOCK_TASK_POOL_TABLE="${BLOCK_TASK_POOL_TABLE}"
  NEW_BLOCK_TX_DETAIL_INFO_TABLE="${BLOCK_TX_DETAIL_INFO_TABLE}"
  NEW_CONTRACT_INFO_TABLE="${CONTRACT_INFO_TABLE}"
  NEW_DEPLOYED_ACCOUNT_INFO="${DEPLOYED_ACCOUNT_INFO}"
  NEW_TX_RAW_DATA="${TX_RAW_DATA}"
  NEW_TX_RECEIPT_RAW_DATA="${TX_RECEIPT_RAW_DATA}"

  cd $BASE_DIR/../$ENTITY_DIR

  if [ "$(uname)" == "Darwin" ]; then
    sed -i "" "s/$BLOCK_DETAIL_INFO_TABLE/$NEW_BLOCK_DETAIL_INFO_TABLE/g" BlockDetailInfo.java
    sed -i "" "s/$BLOCK_RAW_DATA_TABLE/$NEW_BLOCK_RAW_DATA_TABLE/g" BlockRawData.java
    sed -i "" "s/$BLOCK_TASK_POOL_TABLE/$NEW_BLOCK_TASK_POOL_TABLE/g" BlockTaskPool.java
    sed -i "" "s/$BLOCK_TX_DETAIL_INFO_TABLE/$NEW_BLOCK_TX_DETAIL_INFO_TABLE/g" BlockTxDetailInfo.java
    sed -i "" "s/$CONTRACT_INFO_TABLE/$NEW_CONTRACT_INFO_TABLE/g" ContractInfo.java
    sed -i "" "s/$DEPLOYED_ACCOUNT_INFO/$NEW_DEPLOYED_ACCOUNT_INFO/g" DeployedAccountInfo.java
    sed -i "" "s/$TX_RAW_DATA/$NEW_TX_RAW_DATA/g" TxRawData.java
    sed -i "" "s/$TX_RECEIPT_RAW_DATA/$NEW_TX_RECEIPT_RAW_DATA/g" TxReceiptRawData.java
  elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    sed -i "s/$BLOCK_DETAIL_INFO_TABLE/$NEW_BLOCK_DETAIL_INFO_TABLE/g" BlockDetailInfo.java
    sed -i "s/$BLOCK_RAW_DATA_TABLE/$NEW_BLOCK_RAW_DATA_TABLE/g" BlockRawData.java
    sed -i "s/$BLOCK_TASK_POOL_TABLE/$NEW_BLOCK_TASK_POOL_TABLE/g" BlockTaskPool.java
    sed -i "s/$BLOCK_TX_DETAIL_INFO_TABLE/$NEW_BLOCK_TX_DETAIL_INFO_TABLE/g" BlockTxDetailInfo.java
    sed -i "s/$CONTRACT_INFO_TABLE/$NEW_CONTRACT_INFO_TABLE/g" ContractInfo.java
    sed -i "s/$DEPLOYED_ACCOUNT_INFO/$NEW_DEPLOYED_ACCOUNT_INFO/g" DeployedAccountInfo.java
    sed -i "s/$TX_RAW_DATA/$NEW_TX_RAW_DATA/g" TxRawData.java
    sed -i "s/$TX_RECEIPT_RAW_DATA/$NEW_TX_RECEIPT_RAW_DATA/g" TxReceiptRawData.java
  fi
fi

cd $BASE_DIR

# init config
cd ../$CODEGEN
mkdir -p $RESOURCE_DIR/
cp -f $BASE_DIR/$APPLICATION_FILE $RESOURCE_DIR/
cp -f $BASE_DIR/$DEF_FILE $RESOURCE_DIR/

LOG_INFO "copy application.properties done."
mkdir -p $JAVA_CODE_DIR/$contractPath
cp -f $BASE_DIR/$CONTRACT_DIR/* $JAVA_CODE_DIR/$contractPath/
mkdir -p ./$CONTRACT_DIR
cp -f $BASE_DIR/$CONTRACT_DIR/* ./$CONTRACT_DIR
LOG_INFO "copy java contract codes done."

# build
cd $BASE_DIR/../
$GRADLE_EXEC clean :$CODEGEN:bootJar
LOG_INFO "$CODEGEN build done"

# run
cd $CODEGEN/$BUILD_DIR
chmod +x WeBankBlockchain*
$JAVACMD -jar WeBankBlockchain*
LOG_INFO "$CODEGEN generate done."
cd $BASE_DIR
cd ..

cd $CORE
mkdir -p $RESOURCE_DIR/
cp -f  $BASE_DIR/$CERT_DIR/ca.crt $RESOURCE_DIR/
# cp -f  ../$CERT_DIR/client.keystore $RESOURCE_DIR/
cp -f  $BASE_DIR/$CERT_DIR/node.crt $RESOURCE_DIR/
cp -f  $BASE_DIR/$CERT_DIR/node.key $RESOURCE_DIR/
cp -f  $BASE_DIR/$CERT_DIR/sdk* $RESOURCE_DIR/
cp -fr  $BASE_DIR/$CERT_DIR/gm $RESOURCE_DIR/


LOG_INFO "copy certs done."


mkdir -p ../$COMMON/$JAVA_CODE_DIR/$contractPath
for file in $BASE_DIR/$CONTRACT_DIR/*
do
  file=${file##*/}
  if [[ $file == *.java ]];
  then
    cp -f $BASE_DIR/$CONTRACT_DIR/$file ../$COMMON/$JAVA_CODE_DIR/$contractPath/
  fi
done
mkdir -p ./$CONTRACT_DIR
cp -f $BASE_DIR/$CONTRACT_DIR/* ./$CONTRACT_DIR
LOG_INFO "copy java contract codes done."


cd $BASE_DIR/../
$GRADLE_EXEC clean :$CORE:bootJar
LOG_INFO "$PROJECT_NAME build done"
cd $BASE_DIR
rm -rf dist
mkdir dist
cp -r $BASE_DIR/../$CORE/$BUILD_DIR .
## mutiple groups
result=$(echo ${system_groupId} | grep ",")
if [[ "$result" != "" ]]
then
	generate_groups
fi
cd $BASE_DIR/$BUILD_DIR
chmod +x WeBankBlockchain*
chmod +x *sh

if [ "$exec" == "run" ];then
LOG_INFO "start to run $BB"
cd $BASE_DIR/$BUILD_DIR
chmod +x WeBankBlockchain*
./start.sh
fi


