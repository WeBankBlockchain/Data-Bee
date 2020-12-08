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
package com.webank.blockchain.data.export.codegen.code.template.face;

import java.util.Map;

/**
 * AtomicParas
 *
 * @Description: AtomicParas
 * @author maojiayu
 * @data Mar 27, 2019 5:07:07 PM
 *
 */
public interface AtomicParas<T> {
    /**
     * @Description: wrap the render data to a map. And the render data is basically read from a pojo.
     * @param: @param t
     * @return: Map<String,Object>
     */
    public Map<String, Object> getMap(T t);

    /**
     * @Description: return the path of template.
     * @return: String
     */
    public String getTemplatePath();

}
