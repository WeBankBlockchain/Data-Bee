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
package com.webank.blockchain.data.export.common.aspect;

import java.io.IOException;
import java.lang.reflect.Method;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * RetryAspect
 *
 * @Description: RetryAspect
 * @author maojiayu
 * @data Aug 9, 2019 10:35:30 AM
 *
 */
@Aspect
@Component
@Slf4j
public class RetryAspect {
    @Pointcut("@annotation(com.webank.blockchain.data.export.common.aspect.Retry)")
    public void RetryPointCut() {
    }

    @Around("RetryPointCut()")
    public Object around(ProceedingJoinPoint point) throws Throwable {
        Method method = ((MethodSignature) point.getSignature()).getMethod();
        Retry retry = method.getAnnotation(Retry.class);
        for (int i = 0; i < retry.times(); i++) {
            try {
                log.debug("The {} times to retry {}", i + 1, method.getName());
                return point.proceed();
            } catch (IOException e) {
                log.error("IOException: {}", e.getMessage());
                Thread.sleep(retry.interval() * 1000);
            }
        }
        throw new IOException();
    }
}
