package com.study.sso.springsecurity.oauth2;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSON;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@RunWith(SpringRunner.class)
@SpringBootTest
 class TestController {

    @Test
    void contextLoads() {
        String url="http://localhost:8080/oauth/token";

        String authorization = HttpUtil.buildBasicAuth("test", "test", CharsetUtil.CHARSET_UTF_8);
        HashMap<String, String> headers = new HashMap<>();//存放请求头，可以存放多个请求头
        headers.put("Authorization", authorization);

        Map<String, Object> map = new HashMap<>();
        map.put("grant_type","authorization_code");
        map.put("code","p3dLS2");
        map.put("client_id","test");
        map.put("redirect_uri","http://client1.com");
        map.put("scope","all");

        String body = HttpUtil.createPost(url).addHeaders(headers).form(map).execute().body();
        System.out.println(body);
        Auth auth = JSONUtil.toBean(body, Auth.class);
        System.out.println(auth.toString());

    }
    @Data
    class Auth
    {
        private String access_token;
        private String token_type;
        private String refresh_token;
        private String expires_in;
        private String scope;
    }



    @Test
    void contextLoadsPassword() {
        String url="http://localhost:8080/oauth/token";

        String authorization = HttpUtil.buildBasicAuth("test", "test", CharsetUtil.CHARSET_UTF_8);
        HashMap<String, String> headers = new HashMap<>();//存放请求头，可以存放多个请求头
        headers.put("Authorization", authorization);

        Map<String, Object> map = new HashMap<>();
        map.put("grant_type","password");
        map.put("code","ftDcU3");
        map.put("username","user");
        map.put("password","123456");
        map.put("scope","all");

        String body = HttpUtil.createPost(url).addHeaders(headers).form(map).execute().body();
        System.out.println(body);
        Auth auth = JSONUtil.toBean(body, Auth.class);
        System.out.println(auth.toString());

    }

    @Test
    void contextLoads2() {
        String url="http://localhost:8080/oauth/token";

        String authorization = HttpUtil.buildBasicAuth("test", "test", CharsetUtil.CHARSET_UTF_8);
        HashMap<String, String> headers = new HashMap<>();//存放请求头，可以存放多个请求头
        headers.put("Authorization", authorization);

        Map<String, Object> map = new HashMap<>();
        map.put("grant_type","password");
        map.put("code","7SCgYl");
        map.put("username","user");
        map.put("password","123456");
        map.put("scope","all");

        String body = HttpUtil.createPost(url).addHeaders(headers).form(map).execute().body();
        System.out.println(body);
        Auth auth = JSONUtil.toBean(body, Auth.class);

        HashMap<String, String> indexHeader = new HashMap<>();//存放请求头，可以存放多个请求头
        indexHeader.put("Authorization", auth.getToken_type()+" "+auth.getAccess_token());
        String body1 = HttpUtil.createGet("http://localhost:8080/index").addHeaders(indexHeader).execute().body();
        System.out.println(body1);

    }
}
