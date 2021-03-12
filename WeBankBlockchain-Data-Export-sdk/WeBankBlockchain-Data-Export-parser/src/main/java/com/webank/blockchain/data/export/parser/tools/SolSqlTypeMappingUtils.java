/**
 * Copyright 2020 Webank.
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.blockchain.data.export.parser.tools;

import org.apache.commons.lang3.StringUtils;

/**
 * SolSqlTypeMappingUtils
 *
 * @Description: SolSqlTypeMappingUtils
 * @author maojiayu
 * @data Apr 27, 2020 4:10:36 PM
 *
 */
public class SolSqlTypeMappingUtils {
    public static String fromSolBasicTypeToSqlType(String solBasicType) {
        if (StringUtils.contains(solBasicType, "[") && StringUtils.contains(solBasicType, "]")) {
            return "varchar(3072)";
        }
        switch (solBasicType) {
            case "address":
                return "varchar(256)";
            case "string":
                return "varchar(2048)";
            case "bytes1":
            case "bytes2":
            case "bytes3":
            case "bytes4":
            case "bytes5":
            case "bytes6":
            case "bytes7":
            case "bytes8":
                return "varchar(64)";
            case "bytes9":
            case "bytes10":
            case "bytes11":
            case "bytes12":
            case "bytes13":
            case "bytes14":
            case "bytes15":
            case "bytes16":
                return "varchar(128)";
            case "bytes17":
            case "bytes18":
            case "bytes19":
            case "bytes20":
            case "bytes21":
            case "bytes22":
            case "bytes23":
            case "bytes24":
                return "varchar(192)";
            case "bytes25":
            case "bytes26":
            case "bytes27":
            case "bytes28":
            case "bytes29":
            case "bytes30":
            case "bytes31":
            case "bytes32":
                return "varchar(256)";
            case "bytes":
                return "varchar(1024)";
            case "bool":
                return "boolean";
            case "uint8":
            case "int8":
                return  "tinyint";
            case "uint16":
            case "int16":
            case "uint24":
            case "int24":
                return "smallint";
            case "uint32":
            case "int32":
            case "uint40":
            case "int40":
            case "uint48":
            case "int48":
            case "uint56":
            case "int56":
            case "uint64":
            case "int64":
                return "int";
            case "uint72":
            case "int72":
            case "uint80":
            case "int80":
            case "uint88":
            case "int88":
            case "uint96":
            case "int96":
            case "uint104":
            case "int104":
            case "uint112":
            case "int112":
            case "uint120":
            case "int120":
            case "uint128":
            case "int128":
            case "uint136":
            case "int136":
            case "uint144":
            case "int144":
            case "uint152":
            case "int152":
            case "uint160":
            case "int160":
            case "uint168":
            case "int168":
            case "uint176":
            case "int176":
            case "uint184":
            case "int184":
            case "uint192":
            case "int192":
            case "uint200":
            case "int200":
            case "uint208":
            case "int208":
            case "uint216":
            case "int216":
            case "uint224":
            case "int224":
            case "uint232":
            case "int232":
            case "uint240":
            case "int240":
            case "uint248":
            case "int248":
            case "uint256":
            case "int256":
                return "bigint";
            default:
                return null;
        }
    }
}
