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
package com.webank.blockchain.data.export.db.service;

import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Service;

/**
 * RepositoryService
 *
 * @Description: RepositoryService
 * @author maojiayu
 * @data Jul 12, 2019 4:41:08 PM
 *
 */
@Service
public class RepositoryService {
    @Autowired
    private Map<String, JpaRepository> repositories;
    @Autowired
    private Map<String, JpaSpecificationExecutor> specifications;

    public Optional<JpaRepository> getRepository(String name) {
        for (String k : repositories.keySet()) {
            if (name.equalsIgnoreCase(k)) {
                return Optional.of(repositories.get(k));
            }
        }
        return Optional.empty();
    }

    public Optional<JpaSpecificationExecutor> getJpaSpecificationExecutor(String name) {
        for (String k : specifications.keySet()) {
            if (name.equalsIgnoreCase(k)) {
                return Optional.of(specifications.get(k));
            }
        }
        return Optional.empty();
    }

}
