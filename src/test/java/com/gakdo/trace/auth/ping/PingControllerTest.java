// 이 파일이 확인하는 것: auth-server 점검 주소(/api/v1/auth/ping).

package com.gakdo.trace.auth.ping;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import com.gakdo.trace.auth.support.WebSliceConfig;

/**
 * auth-server의 ping(점검) 주소 시험. 배포 뒤 "서버가 떴는지, 어떤 버전·커밋이 돌고 있는지" 확인할 때 부르는 주소다.
 * 컨트롤러만 띄우는 가벼운 시험(DB·메시지 큐 없음)이며, 커밋 값은 test-sha로 고정해 응답에 그대로 나오는지 본다.
 */
@WebMvcTest(controllers = PingController.class, properties = "app.commit=test-sha")
@Import(WebSliceConfig.class)
class PingControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // [상황] 점검 주소를 부른다.
    // [기대] 서비스 이름 auth-server·상태 ok·배포 커밋을 돌려준다.
    @Test
    void ping() throws Exception {
        mockMvc.perform(get("/api/v1/auth/ping"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("auth-server"))
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.commit").value("test-sha"));
    }
}
