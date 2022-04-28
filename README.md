# springsecurity-oauth2

key为Authorization，value为Basic加上client_id:client_secret经过base64加密后的值（可以使用http://tool.chinaz.com/Tools/Base64.aspx）:

[OAuth](https://oauth.net/2/)是一种用来规范令牌（Token）发放的授权机制，主要包含了四种授权模式：授权码模式、简化模式、密码模式和客户端模式。Spring Security OAuth2对这四种授权模式进行了实现。这节主要记录下什么是OAuth2以及Spring Security OAuth2的基本使用。

## 四种授权模式

在了解这四种授权模式之前，我们需要先学习一些和OAuth相关的名词。举个社交登录的例子吧，比如在浏览器上使用QQ账号登录虎牙直播，这个过程可以提取出以下几个名词：

1. **Third-party application** 第三方应用程序，比如这里的虎牙直播；
2. **HTTP service** HTTP服务提供商，比如这里的QQ（腾讯）;
3. **Resource Owner** 资源所有者，就是QQ的所有人，你；
4. **User Agent** 用户代理，这里指浏览器；
5. **Authorization server** 认证服务器，这里指QQ提供的第三方登录服务；
6. **Resource server** 资源服务器，这里指虎牙直播提供的服务，比如高清直播，弹幕发送等（需要认证后才能使用）。

认证服务器和资源服务器可以在同一台服务器上，比如前后端分离的服务后台，它即供认证服务（认证服务器，提供令牌），客户端通过令牌来从后台获取服务（资源服务器）；它们也可以不在同一台服务器上，比如上面第三方登录的例子。

大致了解了这几个名词后，我们开始了解四种授权模式。

### 授权码模式

A. 客户端将用户导向认证服务器；

B. 用户决定是否给客户端授权；

C. 同意授权后，认证服务器将用户导向客户端提供的URL，并附上授权码；

D. 客户端通过重定向URL和授权码到认证服务器换取令牌；

E. 校验无误后发放令牌。

其中A步骤，客户端申请认证的URI，包含以下参数：

1. response_type：表示授权类型，必选项，此处的值固定为”code”，标识授权码模式
2. client_id：表示客户端的ID，必选项
3. redirect_uri：表示重定向URI，可选项
4. scope：表示申请的权限范围，可选项
5. state：表示客户端的当前状态，可以指定任意值，认证服务器会原封不动地返回这个值。

D步骤中，客户端向认证服务器申请令牌的HTTP请求，包含以下参数：

1. grant_type：表示使用的授权模式，必选项，此处的值固定为”authorization_code”。
2. code：表示上一步获得的授权码，必选项。
3. redirect_uri：表示重定向URI，必选项，且必须与A步骤中的该参数值保持一致。
4. client_id：表示客户端ID，必选项。

### 密码模式

在密码模式中，用户像客户端提供用户名和密码，客户端通过用户名和密码到认证服务器获取令牌。

A. 用户向客户端提供用户名和密码；

B. 客户端向认证服务器换取令牌；

C. 发放令牌。

B步骤中，客户端发出的HTTP请求，包含以下参数：

1. grant_type：表示授权类型，此处的值固定为”password”，必选项。
2. username：表示用户名，必选项。
3. password：表示用户的密码，必选项。
4. scope：表示权限范围，可选项。

## Spring Security OAuth2

Spring框架对OAuth2协议进行了实现，下面学习下上面两种模式在Spring Security OAuth2相关框架的使用。

Spring Security OAuth2主要包含认证服务器和资源服务器这两大块的实现：

![QQ截图20190624155418.png](../springsecurity/doc/624155418.png)

认证服务器主要包含了四种授权模式的实现和Token的生成与存储，我们也可以在认证服务器中自定义获取Token的方式（后面会介绍到）；资源服务器主要是在Spring Security的过滤器链上加了OAuth2AuthenticationProcessingFilter过滤器，即使用OAuth2协议发放令牌认证的方式来保护我们的资源。

### 配置认证服务器

新建一个Spring Boot项目，版本为2.2.6.RELEASE，并引入相关依赖，pom如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.2.6.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <groupId>com.study.sso</groupId>
    <artifactId>springsecurity-oauth2</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <java.version>1.8</java.version>
        <spring-cloud.version>Greenwich.SR1</spring-cloud.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-http</artifactId>
            <version>5.6.0</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-json</artifactId>
            <version>5.6.0</version>
        </dependency>
    </dependencies>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring-cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

在创建认证服务器前，我们先定义一个`MyUser`对象：

```java
package com.study.sso.springsecurity.oauth2.entity;

import lombok.Data;

import java.io.Serializable;

@Data
public class MyUser implements Serializable {
    private static final long serialVersionUID = 3497935890426858541L;

    private String userName;
    private String password;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked= true;
    private boolean credentialsNonExpired= true;
    private boolean enabled= true;
}
```

接着定义`UserDetailService`实现`org.springframework.security.core.userdetails.UserDetailsService`接口：

```
package com.study.sso.springsecurity.oauth2.service;


import com.study.sso.springsecurity.oauth2.entity.MyUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserDetailService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MyUser user = new MyUser();
        user.setUserName(username);
        user.setPassword(this.passwordEncoder.encode("123456"));
        return new User(username, user.getPassword(), user.isEnabled(),
                user.isAccountNonExpired(), user.isCredentialsNonExpired(),
                user.isAccountNonLocked(), AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
```

这里的逻辑是用什么账号登录都可以，但是密码必须为123456，并且拥有”admin”权限。

接下来开始创建一个认证服务器，并且在里面定义`UserDetailService`需要用到的`PasswordEncoder`。

创建认证服务器很简单，只需要在Spring Security的配置类上使用`@EnableAuthorizationServer`注解标注即可。创建`AuthorizationServerConfig`，代码如下所示：

```java
package com.study.sso.springsecurity.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

这时候启动项目，会发现控制台打印出了随机分配的client-id和client-secret：

```
security.oauth2.client.client-id = aa726c7e-c728-45e5-9438-f3cba2cf90e2
security.oauth2.client.client-secret = 5a92b72e-7949-4c5b-9617-20cd9b261d50
```

为了方便后面的测试，我们可以手动指定这两个值。在Spring Boot配置文件application.yml中添加如下配置:

```java
security:
  oauth2:
    client:
      client-id: test
      client-secret: test
      registered-redirect-uri: http://client1.com
```

重启项目，发现控制台输出：

```
security.oauth2.client.client-id = test
security.oauth2.client.client-secret = ****
```

说明替换成功。

### 授权码模式获取令牌

接下来开始往认证服务器请求授权码。打开浏览器，访问<http://localhost:8080/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://client1.com&scope=all&state=hello>

URL中的几个参数在上面的授权码模式的A步骤里都有详细说明。

这里response_type必须为code，表示授权码模式，

client_id就是刚刚在配置文件中手动指定的test，

redirect_uri这里随便指定一个地址即可，

主要是用来重定向获取授权码的，

scope指定为all，表示所有权限。

访问这个链接后，页面如下所示：

![1649931827536](../springsecurity/doc/1649931827536-1650002170048.png)

需要登录认证，根据我们前面定义的`UserDetailService`逻辑，这里用户名随便输，密码为123456即可。输入后，页面跳转如下所示：

![1649986639839](../springsecurity/doc/1649986639839-1650002170048.png)

选择同意Approve，然后点击Authorize按钮后，页面跳转到了我们指定的redirect_uri，并且带上了授权码信息:



![1649932163896](../springsecurity/doc/1649932163896-1650002170049.png)



可以编写测试类或者Postman都可以，我这里采用的是使用测试类：

```java
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
        map.put("code","5wLCxf");
        map.put("client_id","test");
        map.put("redirect_uri","http://client1.com");
        map.put("scope","all");

        String body = HttpUtil.createPost(url).addHeaders(headers).form(map).execute().body();
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
}

```

执行成功后就显示了

![1649931633585](../springsecurity/doc/1649931633585-1650002170049.png)

一个授权码只能换一次令牌，如果再次点击postman的发送按钮，将返回：

![1649987335534](../springsecurity/doc/1649987335534-1650002170049.png)

### 密码模式获取令牌

和授权码模式相比，使用密码模式获取令牌就显得简单多了。同样使用测试工具类发送POST请求

```java
@Test
void contextLoadsPassword() {
    String url="http://localhost:8080/oauth/token";

    String authorization = HttpUtil.buildBasicAuth("test", "test", CharsetUtil.CHARSET_UTF_8);
    HashMap<String, String> headers = new HashMap<>();//存放请求头，可以存放多个请求头
    headers.put("Authorization", authorization);

    Map<String, Object> map = new HashMap<>();
    map.put("grant_type","password");
    map.put("code","w38kyV");
    map.put("username","user");
    map.put("password","123456");
    map.put("scope","all");

    String body = HttpUtil.createPost(url).addHeaders(headers).form(map).execute().body();
    System.out.println(body);
    Auth auth = JSONUtil.toBean(body, Auth.class);
    System.out.println(auth.toString());

}
```

grant_type填password，表示密码模式；然后填写用户名和密码，头部也需要填写Authorization信息，内容和授权码模式介绍的一致，这里就不截图了。

点击发送，也可以获得令牌：

```
TestController.Auth(access_token=c0b0e4f8-f73a-49d5-b9d5-883a21e2d410, token_type=bearer, refresh_token=485e8976-73db-447d-98bc-d123d0f43927, expires_in=43199, scope=all)
```

### 配置资源服务器

为什么需要资源服务器呢？我们先来看下在没有定义资源服务器的时候，使用Token去获取资源时会发生什么。

```java
package com.study.sso.springsecurity.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("index")
    public Object index(Authentication authentication){
        return authentication;
    }
}
```

启动项目，为了方便我们使用密码模式获取令牌，然后使用该令牌获取`/index`这个资源：

Authorization值为`token_type access_token`，发送请求后，返回：

![1649988926201](../springsecurity/doc/1649988926201-1650002170049.png)

虽然令牌是正确的，但是并无法访问`/index`，所以我们必须配置资源服务器，让客户端可以通过合法的令牌来获取资源。

资源服务器的配置也很简单，只需要在配置类上使用`@EnableResourceServer`注解标注即可：

```java
package com.study.sso.springsecurity.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@Configuration
@EnableResourceServer
public class ResourceServerConfig  {

}
```

重启服务，重复上面的步骤，再次访问http://localhost:8080/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://client1.com&scope=all&state=hello 地址获取token，会出现这个问题

![1649989107486](../springsecurity/doc/1649989107486-1650002170049.png)

这个是由于在同时定义了认证服务器和资源服务器后，再去使用授权码模式获取令牌有可能遇到的问题，这时候只要确保认证服务器先于资源服务器配置即可，比如在认证服务器的配置类上使用`@Order(1)`标注，在资源服务器的配置类上使用`@Order(2)`标注。 注意Order后，它的加载顺序是有问题的，所以有可能出现401，最好不要加，我加上后，上方错误不出现了，但是一直401，所以我又去掉了

接下来我们再次重启服务，重复上面的步骤，访问http://localhost:8080/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://client1.com&scope=all&state=hello 地址获取token

![1649989289052](../springsecurity/doc/1649989289052-1650002170049.png)

![1649989302874](../springsecurity/doc/1649989302874-1650002170049.png)

授权完成后，获取code码，

![1649989321982](../springsecurity/doc/1649989321982-1650002170049.png)

通过code码再去获取access_token和token_type

![1649989393857](../springsecurity/doc/1649989393857-1650002170049.png)

然后接着去访问http://localhost:8080/index 就可以拿到信息了

![1649992741846](../springsecurity/doc/1649992741846-1650002170049.png)

## Spring Security OAuth2自定义Token获取方式

如何通过自定义的用户名密码和手机短信验证码的方式来获取令牌。

### 自定义用户名密码方式获取令牌

们先在资源服务器上加入一些基本的Spring Security配置:

```java
package com.study.sso.springsecurity.oauth2.config;

import com.study.sso.springsecurity.oauth2.handler.MyAuthenticationFailureHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@Configuration
@EnableResourceServer

public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;
    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.formLogin() // 表单登录
                .loginProcessingUrl("/login") // 处理表单登录 URL
                .successHandler(authenticationSucessHandler) // 处理登录成功
                .failureHandler(authenticationFailureHandler) // 处理登录失败
                .and()
                .authorizeRequests() // 授权配置
                .anyRequest()  // 所有请求
                .authenticated() // 都需要认证
                .and()
                .csrf().disable();
    }
}
```

`MyAuthenticationFailureHandler`失败处理器的逻辑很简单，就是认证失败放回相应提示：

```java
@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Autowired
    private ObjectMapper mapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(mapper.writeValueAsString(exception.getMessage()));
    }
}
```

  问题的关键是，如何在登录成功处理器里返回令牌。在研究Spring Security OAuth2自带的令牌获取方式后，会发现令牌的产生可以归纳为以下几个步骤：



![624223930.png](../springsecurity/doc/624223930.png)

我们可以参考这个流程，来实现在登录成功处理器`MyAuthenticationSucessHandler`里生成令牌并返回：

![1649994354347](../springsecurity/doc/1649994354347-1650002170049.png)

使用这个令牌便可以成功访问`/index`接口

![1649994420307](../springsecurity/doc/1649994420307-1650002170049.png)

### 短信验证码获取令牌

我们使用第三方存储来保存我们的验证码（无论是短信验证码还是图形验证码都是一个道理），比如Redis等。

引入Redis依赖：

```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

定义一个`RedisCodeService`，用于验证码的增删改：

```java
package com.study.sso.springsecurity.oauth2.service;

import com.study.sso.springsecurity.oauth2.entity.SmsCode;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.concurrent.TimeUnit;

/**
 * Redis操作验证码服务
 */
@Service
public class RedisCodeService {

    private final static String SMS_CODE_PREFIX = "SMS_CODE:";
    private final static Integer TIME_OUT = 300;

    @Autowired
    private StringRedisTemplate redisTemplate;

    /**
     * 保存验证码到 redis
     *
     * @param smsCode 短信验证码
     * @param request ServletWebRequest
     */
    public void save(SmsCode smsCode, ServletWebRequest request, String mobile) throws Exception {
        redisTemplate.opsForValue().set(key(request, mobile), smsCode.getCode(), TIME_OUT, TimeUnit.SECONDS);
    }

    /**
     * 获取验证码
     *
     * @param request ServletWebRequest
     * @return 验证码
     */
    public String get(ServletWebRequest request, String mobile) throws Exception {
        return redisTemplate.opsForValue().get(key(request, mobile));
    }

    /**
     * 移除验证码
     *
     * @param request ServletWebRequest
     */
    public void remove(ServletWebRequest request, String mobile) throws Exception {
        redisTemplate.delete(key(request, mobile));
    }

    private String key(ServletWebRequest request, String mobile) throws Exception {
        String deviceId = request.getHeader("deviceId");
        if (StringUtils.isBlank(deviceId)) {
            throw new Exception("请在请求头中设置deviceId");
        }
        return SMS_CODE_PREFIX + deviceId + ":" + mobile;
    }
}
```

再定义一个SMSCode的短信基本类

```java
package com.study.sso.springsecurity.oauth2.entity;

import lombok.Data;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * 短信验证码对象SmsCode
 */
@Data
public class SmsCode implements Serializable {
    /**
     * 验证码
     */
    private String code;
    /**
     * 过期时间
     */
    private LocalDateTime expireTime;

    public SmsCode(String code, int expireIn) {
        this.code = code;
        this.expireTime = LocalDateTime.now().plusSeconds(expireIn);
    }

    public SmsCode(String code, LocalDateTime expireTime) {
        this.code = code;
        this.expireTime = expireTime;
    }

    /**
     * isExpire方法用于判断短信验证码是否已过期。
     * @return
     */
    public boolean isExpire() {
        return LocalDateTime.now().isAfter(expireTime);
    }
}
```

配置文件添加关于redis的配置

```java
spring:
  redis:
    host: 10.10.4.76
```

同时配置"/code/sms"这个请求路径不需要拦截

同时控制器当中编写

```java
@GetMapping("/code/sms")
public void createSmsCode(HttpServletRequest request, HttpServletResponse response, String mobile) throws Exception {
    SmsCode smsCode = createSMSCode();
    redisCodeService.save(smsCode,new ServletWebRequest(request),mobile);
    // 短信发送服务
    System.out.println("您的登录验证码为：" + smsCode.getCode() + "，有效时间为60秒");
}

private SmsCode createSMSCode() {
    String code = RandomStringUtils.randomNumeric(6);
    return new SmsCode(code, 60);
}
```

启动系统，使用postman发送验证码：请求头中带上deviceId（这里为随便填写的模拟值）：

![1649999097852](../springsecurity/doc/1649999097852-1650002170049.png)

![1649999208456](../springsecurity/doc/1649999208456-1650002170049.png)

接着用这个验证码去换取令牌，使用postman发送如下请求：

![1649999841128](../springsecurity/doc/1649999841128-1650002170049.png)

## Spring Security OAuth2自定义令牌配置



在前面几节中，我们获取到的令牌都是基于Spring Security OAuth2默认配置生成的，Spring Security允许我们自定义令牌配置，比如不同的client_id对应不同的令牌，令牌的有效时间，令牌的存储策略等；我们也可以使用JWT来替换默认的令牌。

###   自定义令牌配置

我们让认证服务器`AuthorizationServerConfig`继承`AuthorizationServerConfigurerAdapter`，并重写它的`configure(ClientDetailsServiceConfigurer clients)`方法：

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    ......

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserDetailService userDetailService;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailService);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("test1")
                .secret("test1111")
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(864000)
                .scopes("all", "a", "b", "c")
                .authorizedGrantTypes("password")
            .and()
                .withClient("test2")
                .secret("test2222")
                .accessTokenValiditySeconds(7200);
    }
}
```

认证服务器在继承了AuthorizationServerConfigurerAdapter适配器后，需要重写`configure(AuthorizationServerEndpointsConfigurer endpoints)`方法，指定 `AuthenticationManager`和`UserDetailService`。

创建一个新的配置类`SecurityConfig`，在里面注册我们需要的`AuthenticationManager`Bean：

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```

此外，重写`configure(ClientDetailsServiceConfigurer clients)`方法主要配置了：

1. 定义两个client_id，及客户端可以通过不同的client_id来获取不同的令牌；
2. client_id为test1的令牌有效时间为3600秒，client_id为test2的令牌有效时间为7200秒；
3. client_id为test1的refresh_token（下面会介绍到）有效时间为864000秒，即10天，也就是说在这10天内都可以通过refresh_token来换取新的令牌；
4. 在获取client_id为test1的令牌的时候，scope只能指定为all，a，b或c中的某个值，否则将获取失败；
5. 只能通过密码模式(password)来获取client_id为test1的令牌，而test2则无限制。

启动项目，演示几个效果。启动项目后使用密码模式获取test1的令牌：

和前面介绍的那样，头部需要传入`test1:test1111`经过base64加密后的值：

![1650001948436](../springsecurity/doc/1650001948436-1650002170049.png)

![1650001898431](../springsecurity/doc/1650001898431-1650002170049.png)

点击发送后，意外的返回了错误！



在新版本的spring-cloud-starter-oauth2指定client_secret的时候需要进行加密处理：

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    ......

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("test1")
                .secret(new BCryptPasswordEncoder().encode("test1111"))
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(864000)
                .scopes("all", "a", "b", "c")
                .authorizedGrantTypes("password")
            .and()
                .withClient("test2")
                .secret(new BCryptPasswordEncoder().encode("test2222"))
                .accessTokenValiditySeconds(7200);
    }
}
```

在前面自定义登录认证获取令牌一节中，我们在`MyAuthenticationSucessHandler`判断了client_secret的值是否正确。由于我们这里client_secret加密了，所以判断逻辑需要调整为下面这样:

```java
`...else if (!passwordEncoder.matches(clientSecret, clientDetails.getClientSecret())) {    throw new UnapprovedClientAuthenticationException("clientSecret不正确");} ...`
```

修改后重启项目，重新使用密码模式获取令牌：

![1650002239943](../springsecurity/doc/1650002239943-1650004227141.png)

可以看到`expires_in`的时间是我们定义的3600秒。

将scope指定为d看看会有什么结果:

![1650002280728](/doc/1650002280728.png)

由于我们定义了只能通过密码模式来获取client_id为test1的令牌，所以我们看看将grant_type改为xxoo会有什么结果:

![1650002419576](../springsecurity/doc/1650002419576-1650004227141.png)

默认令牌是存储在内存中的，我们可以将它保存到第三方存储中，比如Redis。

创建`TokenStoreConfig`：

```java
@Configuration
public class TokenStoreConfig {

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Bean
    public TokenStore redisTokenStore (){
        return new RedisTokenStore(redisConnectionFactory);
    }
}
```

然后在认证服务器里指定该令牌存储策略。重写`configure(AuthorizationServerEndpointsConfigurer endpoints)`方法：

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private TokenStore redisTokenStore;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
            .tokenStore(redisTokenStore);
    }

    ......
}
```

重启项目获取令牌后，查看Redis中是否存储了令牌相关信息：

![1650002654949](../springsecurity/doc/1650002654949-1650004227141.png)

可以看到，令牌信息已经存储到Redis里了。

### 使用JWT替换默认令牌

使用JWT替换默认的令牌（默认令牌使用UUID生成）只需要指定TokenStore为JwtTokenStore即可。

创建一个`JWTokenConfig`配置类：

```java
package com.study.sso.springsecurity.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class JWTokenConfig {

    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        accessTokenConverter.setSigningKey("test_key"); // 签名密钥
        return accessTokenConverter;
    }
}
```

签名密钥为`test_key`。在配置类里配置好`JwtTokenStore`后，我们在认证服务器里指定它：

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private TokenStore jwtTokenStore;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
                .tokenStore(jwtTokenStore)
                .accessTokenConverter(jwtAccessTokenConverter);
    }

    ......
}
```

重启服务时出现失败：

![1650002967979](../springsecurity/doc/1650002967979-1650004227141.png)

这是因为我们里边设置了两个令牌，由于我们现在是要测试jwt，所以先把redis的给去注释掉

重启服务获取令牌，系统将返回如下格式令牌：

![1650003045251](../springsecurity/doc/1650003045251-1650004227141.png)

将`access_token`中的内容复制到<https://jwt.io/>网站解析下：

![1650003146438](../springsecurity/doc/1650003146438-1650004227141.png)

### 拓展JWT

上面的Token解析得到的PAYLOAD内容为：

```
{
  "exp": 1650006637,
  "user_name": "test1",
  "authorities": [
    "admin"
  ],
  "jti": "bca3b773-5cf8-4da8-8215-43dc79e83d33",
  "client_id": "test1",
  "scope": [
    "all"
  ]
}
```

如果想在JWT中添加一些额外的信息，我们需要实现`TokenEnhancer`（Token增强器）：

```java
public class JWTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        Map<String, Object> info = new HashMap<>();
        info.put("message", "hello world");
        ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(info);
        return oAuth2AccessToken;
    }
}
```

我们在Token中添加了`message: hello world`信息。然后在`JWTokenConfig`里注册该Bean：

```java
@Configuration
public class JWTokenConfig {
    ......

    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new JWTokenEnhancer();
    }
}
```

最后在认证服务器里配置该增强器：

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private TokenStore jwtTokenStore;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    @Autowired
    private TokenEnhancer tokenEnhancer;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> enhancers = new ArrayList<>();
        enhancers.add(tokenEnhancer);
        enhancers.add(jwtAccessTokenConverter);
        enhancerChain.setTokenEnhancers(enhancers);

        endpoints.tokenStore(jwtTokenStore)
                .accessTokenConverter(jwtAccessTokenConverter)
                .tokenEnhancer(enhancerChain);
    }
    ......
}
```

重启项目，再次获取令牌，系统返回：

```java
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJtcmJpcmQiLCJzY29wZSI6W10sImV4cCI6MTU2MTUzNDQ1MCwibWVzc2FnZSI6ImhlbGxvIHdvcmxkIiwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiY2E1NDA3ZTEtMzBmZS00MzA3LThiYmItYjU2NGY5Y2ViOWUzIiwiY2xpZW50X2lkIjoidGVzdDEifQ.qW92ssifRKi_rxX2XIH2u4D5IUPVcKECv812hTpuUuA",
    "token_type": "bearer",
    "expires_in": 3599,
    "message": "hello world",
    "jti": "ca5407e1-30fe-4307-8bbb-b564f9ceb9e3"
}
```

### Java中解析JWT

要在Java代码中解析JWT，需要添加如下依赖：

```
`<dependency>    <groupId>io.jsonwebtoken</groupId>    <artifactId>jjwt</artifactId>    <version>0.9.1</version></dependency>`
```

修改`/index`：

```java
@GetMapping("index")
public Object index(@AuthenticationPrincipal Authentication authentication, HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    String token = StringUtils.substringAfter(header, "bearer ");

    return Jwts.parser().setSigningKey("test_key".getBytes(StandardCharsets.UTF_8)).parseClaimsJws(token).getBody();
}
```

signkey需要和`JwtAccessTokenConverter`中指定的签名密钥一致。重启项目，获取令牌后访问`/index`,

![1650004612313](doc/1650004612313.png)

输出内容如下：

```
{
    "exp": 1650008088,
    "user_name": "test1",
    "authorities": [
        "admin"
    ],
    "jti": "bd5e9cc4-6032-4481-b491-253737dcccca",
    "client_id": "test1",
    "scope": [
        "all"
    ]
}
```

### 刷新令牌

令牌过期后我们可以使用refresh_token来从系统中换取一个新的可用令牌。但是从前面的例子可以看到，在认证成功后返回的JSON信息里并没有包含refresh_token，要让系统返回refresh_token，需要在认证服务器自定义配置里添加如下配置：

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	......

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("test1")
                .secret(new BCryptPasswordEncoder().encode("test1111"))
                .authorizedGrantTypes("password", "refresh_token")
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(864000)
                .scopes("all", "a", "b", "c")
            .and()
                .withClient("test2")
                .secret(new BCryptPasswordEncoder().encode("test2222"))
                .accessTokenValiditySeconds(7200);
    }
}
```

授权方式需要加上`refresh_token`，除了四种标准的OAuth2获取令牌方式外，Spring Security OAuth2内部把`refresh_token`当作一种拓展的获取令牌方式。

通过上面的配置，使用test1这个client_id获取令牌时将返回refresh_token，refresh_token的有效期为10天，即10天之内都可以用它换取新的可用令牌。

重启项目，认证成功后，系统返回如：

![1650004787552](doc/1650004787552.png)

假设现在access_token过期了，我们用refresh_token去换取新的令牌。使用postman发送如下请求：

![1650004980106](doc/1650004980106.png)

![1650004951480](doc/1650004951480.png)

学习地址：https://github.com/wuyouzhuguli/SpringAll 