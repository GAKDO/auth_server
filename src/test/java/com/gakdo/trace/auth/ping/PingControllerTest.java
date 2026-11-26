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
// (도구) @WebMvcTest = 서버 전체 대신 지정한 컨트롤러(PingController)만 띄우는 가벼운 API 테스트. properties로 커밋 값을 test-sha로 고정한다
@WebMvcTest(controllers = PingController.class, properties = "app.commit=test-sha")
// 운영과 같은 보안 규칙도 함께 띄운다
@Import(WebSliceConfig.class)
class PingControllerTest {

    // (도구) MockMvc = 진짜 네트워크 없이 서버에 HTTP 요청을 보낸 것처럼 흉내 내는 도구. @Autowired = 스프링이 만들어 넣어 준다
    @Autowired
    private MockMvc mockMvc;

    // [상황] 점검 주소를 부른다.
    // [기대] 서비스 이름 auth-server·상태 ok·배포 커밋을 돌려준다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시
    @Test
    void ping() throws Exception {
        // (도구) perform(get(주소)) = GET 요청을 보낸다. andExpect(...) = 응답이 이래야 한다는 검사
        // 실행: 로그인 없이 점검 주소를 부른다
        mockMvc.perform(get("/api/v1/auth/ping"))
                // (도구) status().isOk() = 응답 코드가 200(정상)인지 본다
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // (도구) jsonPath("$.칸") = 응답 JSON에서 그 칸 값을 꺼낸다. value(값) = 그 값과 같은지 본다
                // 확인: 서비스 이름이 auth-server여야 한다
                .andExpect(jsonPath("$.service").value("auth-server"))
                // 확인: 상태가 ok여야 한다
                .andExpect(jsonPath("$.status").value("ok"))
                // 확인: 배포 커밋이 고정해 둔 test-sha로 나와야 한다 = 어떤 커밋이 돌고 있는지 알 수 있다
                .andExpect(jsonPath("$.commit").value("test-sha"));
    }
}
