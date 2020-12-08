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
package com.webank.blockchain.data.export.db.tools;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.util.ObjectUtil;
import lombok.extern.slf4j.Slf4j;

/**
 * QueryUtils
 *
 * @Description: QueryUtils
 * @author maojiayu
 * @data Jun 28, 2020 5:10:00 PM
 *
 */
@Slf4j
@SuppressWarnings({ "unchecked", "all" })
public class QueryUtils {

    public static <R, Q> Predicate getPredicate(Root<R> root, Q query, CriteriaBuilder cb) {
        List<Predicate> list = new ArrayList<>();
        if (query == null) {
            return cb.and(list.toArray(new Predicate[0]));
        }
        try {
            List<Field> fields = getAllFields(query.getClass(), new ArrayList<>());
            for (Field field : fields) {
                field.setAccessible(true);
                QueryPredicateBean bean = new QueryPredicateBean().fromQuery(query, field);
                if (bean.getQueryAnnotation() != null) {
                    if (ObjectUtil.isNull(bean.getValue()) || "".equals(bean.getValue())) {
                        continue;
                    }
                    if (ObjectUtil.isNotEmpty(bean.getBlurry())) {
                        list.addAll(handleBlurry(bean, root, cb));
                        continue;
                    }
                    list.addAll(handleType(bean, root, cb));
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        int size = list.size();
        return cb.and(list.toArray(new Predicate[size]));
    }

    public static List<Field> getAllFields(Class clazz, List<Field> fields) {
        if (clazz != null) {
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            getAllFields(clazz.getSuperclass(), fields);
        }
        return fields;
    }

    public static <R> List<Predicate> handleBlurry(QueryPredicateBean bean, Root<R> root, CriteriaBuilder cb) {
        List<Predicate> list = new ArrayList<>();
        String[] blurrys = bean.getBlurry().split(",");
        List<Predicate> orPredicate = new ArrayList<>();
        for (String s : blurrys) {
            orPredicate.add(cb.like(root.get(s).as(String.class), "%" + bean.getValue().toString() + "%"));
        }
        Predicate[] p = new Predicate[orPredicate.size()];
        list.add(cb.or(orPredicate.toArray(p)));
        return list;
    }

    public static <R> List<Predicate> handleType(QueryPredicateBean bean, Root<R> root, CriteriaBuilder cb) {
        List<Predicate> list = new ArrayList<>();
        switch (bean.getQueryAnnotation().type()) {
            case EQUAL:
                list.add(cb.equal(
                        root.get(bean.getAttributeName()).as((Class<? extends Comparable>) bean.getFieldType()),
                        bean.getValue()));
                break;
            case GREATER_THAN:
                list.add(cb.greaterThanOrEqualTo(
                        root.get(bean.getAttributeName()).as((Class<? extends Comparable>) bean.getFieldType()),
                        (Comparable) bean.getValue()));
                break;
            case LESS_THAN:
                list.add(cb.lessThanOrEqualTo(
                        root.get(bean.getAttributeName()).as((Class<? extends Comparable>) bean.getFieldType()),
                        (Comparable) bean.getValue()));
                break;
            case LESS_THAN_NQ:
                list.add(cb.lessThan(
                        root.get(bean.getAttributeName()).as((Class<? extends Comparable>) bean.getFieldType()),
                        (Comparable) bean.getValue()));
                break;
            case INNER_LIKE:
                list.add(cb.like(root.get(bean.getAttributeName()).as(String.class),
                        "%" + bean.getValue().toString() + "%"));
                break;
            case LEFT_LIKE:
                list.add(cb.like(root.get(bean.getAttributeName()).as(String.class), "%" + bean.getValue().toString()));
                break;
            case RIGHT_LIKE:
                list.add(cb.like(root.get(bean.getAttributeName()).as(String.class), bean.getValue().toString() + "%"));
                break;
            case IN:
                if (CollUtil.isNotEmpty((Collection<Long>) bean.getValue())) {
                    list.add(root.get(bean.getAttributeName()).in((Collection<Long>) bean.getValue()));
                }
                break;
            case NOT_EQUAL:
                list.add(cb.notEqual(root.get(bean.getAttributeName()), bean.getValue()));
                break;
            case NOT_NULL:
                list.add(cb.isNotNull(root.get(bean.getAttributeName())));
                break;
            case IS_NULL:
                list.add(cb.isNull(root.get(bean.getAttributeName())));
                break;
            case BETWEEN:
                List<Object> between = new ArrayList<>((List<Object>) bean.getValue());
                list.add(cb.between(
                        root.get(bean.getAttributeName()).as((Class<? extends Comparable>) between.get(0).getClass()),
                        (Comparable) between.get(0), (Comparable) between.get(1)));
                break;
            default:
                break;
        }
        return list;
    }
}
