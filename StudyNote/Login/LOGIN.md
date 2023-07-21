# 간단한 로그인 구현(Spring-Security + JWT) 및 부가 지식들
> 로그인 코드에 대해 설명하기 전에 로그인에 대한 상황을 한번 알아보자.
### WHEN
* HTTP는 Stateless 하기 때문에 서버(네이버)와 나(클라이언트) 간의 통신 상태를 저장하지 않는다.
* 현재 나는 로그인을 하였고 나의 블로그에 들어간다고 하자
### GIVEN
* 나는 분명히 로그인을 하였고 나의 블로그를 들어갈려고 했지만 로그인을 하라면서 로그인 화면으로 넘어간다
* why? : 내가 현재 로그인 한 상태를 서버는 유지하지 않기 때문이다.
### THEN
* `세션`과 `토큰`을 사용하자

* 세션과 토큰은 **인증**과 **인가**를 위해 사용한다
1. 유저가 로그인을 시도하면 서버 상에서 일치하는 유저 정보를 찾는다
2. 인증 확인의 표시로 세션이나 토큰을 발급한다
3. 웹 브라우저 측에 세션/토큰을 가지고 있는다
4. 새로운 요청을 보낼 때마다 인가를 위해 세션/토큰을 함께 보낸다.

> 세션과 토큰의 차이점
* 세션은 데이터베이스 서버에 저장되어 요청의 session_id 와 데이터베이스에 있는 테이블을 보고 확인한다.
* 토큰은 나의 토큰만을 보고 해당 토큰이 유효한지를 확인한다.

### 사이즈
* 인가를 위해 세션을 보낼 때는 session_id 만 보내기 때문에 사이즈가 작다
* 토큰을 보낼 때는 Jwtf를 보내는데 세션ID에 비해 사이즈가 크다

### 안정성
* 세션: 데이터베이스 서버 측에서 저장 및 관리를 하기 때문에 상대적으로 유지하기 유리하다. 물론 공격으로부터 자유로운 것은 아니므로 유효기간, Secure 옵션 등을 주어 쿠키에 저장한다
* 토큰 : 웹 스토리지 등에 보관되기 때문에 공격에 노출될 가능성이 높다.
    * 민감한 정보를 담지 않는다
    * 유효기간을 짧게 설정한다
        * 유효기간이 짧아서 토큰이 무효화되면 그 때마다 새로 로그인해야한다
        * -> 로그인 인증 시 Refresh Token을 발급한다
            * 기존 토큰이 만료되거나 변질되면 refresh Token을 통해 재발급한다

### 확장성(대규모 시스템 설계 개념을 추가한…)
* 세션 : 서버에 저장이되므로 트래픽이 쏠리면 과부하가 걸릴 수 있다
    * 해결방안 1 : 서버를 여러 개 두고 로드 밸런서를 통해 트래픽을 낮춘다
    * 해결방안 1의 문제점 : 다중화된 서버에는 중복이 없기 때문에 서버마다 저장된 세션은 다르다 -> 요청 할 때마다 접속한 서버가 다르면 나의 세션이 존재하지 않을 수 있다
        * 해결방안 1 문제점의 해결방안 : Stickey Session을 사용해서 처음 요청을 처리한(예를 들어 나의 세션ID를 발급해준 서버라던가) 서버에만 요청을 하도록 고정한다.
            * 해결방안 1 문제점의 해결방안의 문제점 : Stickey Session의 문제점인 특정 서버의 과부화, 로드 밸런싱의 기능 손실 가능성, 특정 서버에서 실패 시 해당 서버에 있는 세션들이 계속 실패
                * 해결방안 1 문제점의 해결방안의 문제점의 해결방안 : 여러 개의 세션을 묶어서, 즉 세션을 클러스터링 해서 관리하자, 아니면 세션 서버의 정보를 적어주고 연결만 해준다(세션 서버를 두자 Redis).
                    * 마지막으로 세션 서버의 다중화도 고려하자…

---
### Jwt를 이용해서 로그인을 구현하자
* 우리는 jwt와 spring security를 이용할 것이므로 라이브러리를 추가하자
```java
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
implementation 'io.jsonwebtoken:jjwt-impl:0.11.5'
implementation 'io.jsonwebtoken:jjwt-jackson:0.11.5'

implementation 'org.springframework.boot:spring-boot-starter-security'

lombok도 사용하므로 build.gradle 파일에 추가해주면 된다.
```

```java
/members/secuirty/TokenInfo
클라이언트에게 보낼 토큰의 정보(DTO)

@Builder // 빌드 패턴을 사용하여 불변형 객체를 생성
@Data // getter, setter
@AllArgsConstructor // 모든 필드 값을 파라메터로 받는 생성자
public class TokenInfo {
    private String grantType;
    private String accessToken;
    private String refreshToken;
}

```

* grantType : 토큰 인증 타입
    * Basic : 사용자 아이디와 암호를 Base64로 인코딩 한 값
        * Base64 : 64진법으로 이진 데이터를 아스키 문자로만 이루어진 텍스트로 변환시키는 인코딩
        * 이진 데이터(8비트 바이트의 연속인 데이터)를 4개의 6비트 Base64 숫자로 나타낼 수 있는 24 비트의 연속으로 변환(8*3 = 6*4)
    * Bearer : Jwt, Oauth에 대한 토큰을 사용(https를 사용해야한다)
        * 헤더와 페이로드를 가지고 서명 필드를 생성한다
    * Digest : 서버에서 난수 데이터 문자열을 클라이언트에게 보내고, 사용자 정보와 난수를 포함하는 해시 값을 사용
    * HOBA : 전자 서명 기반 인증 방식

---
> 오랜만에 정보보안에 대해 상기해보자(공개키 - 비밀키)
> 3학년 2학기로 돌아가보자….
> 1. 공개키는 비밀키를 통해 생성된다.(즉, 공개키는 비밀키에 의해 해독될 수 있다.
> 2. 공개키는 서버 상 모두에게 공개된다.
> 3. A가 B에게 데이터를 안전하게 보내고 싶다면 A는 B의 공개키로 암호화한다음에 B에게 보내면된다.
> 4. B는 받은 암호화된 데이터를 자신의 B 비밀키로 해독한다.
* 우리는 grantType으로 Bearer을 사용할 것이다.
* Application.properties에 비밀 키를 추가하자
```java
jwt:
  secret:VlwEyVBsYt9V7zq57TejMnVUyzblYcfPQye08f7MGVA9XkHa
```

* 토큰 암호/복호화를 위한 비밀키로 HS256을 사용할 것이므로, 비밀키는 256비트(8*32)보다 크면 된다.
* HS256(HMAC with SHA-256) : 대칭 키를 사용하는 알고리즘. A,B가 서로 같은 Key를 공유하고, 한쪽에서 데이터와 key를 해시 함수에 넣은 값과 데이터를 보낸다. 받는 사람도 똑같이 데이터와 key를 해시 함수에 넣고 해당 값을 받은 값과 비교하고 만약에 동일하면 해당 데이터 값을 신뢰한다.
* RS256(RSA with SHA-256) : RSA를 이용해서 비대칭키 방식을 사용하는 것. 동작 방식은 위 공개키-비밀키 동작 방식과 비슷하다
* SHA-256 : 해시 함수로 간단하게 설명하면 메세지(혹은 데이터)를 여러개 의 사이즈가 동일 블록으로 나누고 각 블록들을 연쇄적으로 해시 함수에 넣는다고 보면 된다(해시 함수는 입력 값이 조금이라도 바뀌면 결과 값은 엄청나게 달라진다는 것을 생각하자).
* RSA : 큰 정수의 소인수분해의 어려움을 사용하는 암호 알고리즘. 근데 여기에 소수를 첨가한… 여기에 페르마의 소정리를 첨가한 …

보안, 성능 측면으로 보면 RS256이 더 좋아보인다. 나중에는 RS256으로 바꿔봐야겠다.

---
### JwtTokenProvider
```java
@Component // JwtTokenProvider를 빈에 등록
@Slf4j // 로깅 프레임 워크
public class JwtTokenProvider {

    private final Key key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public TokenInfo generateToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();

        Date accessTokenExipresIn = new Date(now + 86400000);
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth",authorities)
                .setExpiration(accessTokenExipresIn)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        String refreshToken = Jwts.builder()
                .setExpiration(new Date(now + 864000000))
                .signWith(key,SignatureAlgorithm.HS256)
                .compact();
        return TokenInfo.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) {
            throw new RuntimeException("Not Authenticated Token");
        }

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails principal = new User(claims.getSubject(),"",authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e ) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e ) {
            log.info("Unsuppported JWT Token");
        } catch (IllegalArgumentException e ) {
            log.info("JWT claims string is empty", e);
        }
        return false;
    }
}

```

* JwtTokenProvider : 키를 만드는 메소드
    1. @Value를 사용해서 secreKey의 값으로 application.properites에 있는 jwt.secret을 넣어주자.
    2. BASE64로 비밀 키를 디코딩 한다(바이트로 변환)
    3. HS256에 넣어서 키를 생성하자
* public TokenInfo generateToken(Authentication authentication)
    1. Authentication -> 인증 요청에 대한 토큰이나 authenticate 메소드에 의해 요청이 처리된 후 인증 된 주체에 대한 토큰을 나타낸다. 요놈은 SecurityContextHolder가 관리하는 쓰레드 로컬 SecurityContext에 저장된다.
    * . 객체에서 권한 정보를 가져온다(컬렉션) -> 가져온 컬렉션을 스트림으로 변환한다 -> 스트림의 요소들(권한 객체)을 문자열로 변환한다 -> “,”를 구분자로 사용해서 문자열로 합친다.
    *  ex) “ROLE_USER”,”ROLE_ADMIN” -> “ROLE_USER,ROLE_ADMIN”
    2. 현재 시간을 가져와서 accessToken의 유효 기간을 8640000(60*60*24), 하루로 설정한다
    3. accessToken 생성: 빌더 ->  사용자의 권한 정보를 설정 -> 만료시간 설정 -> 토큰 서명 -> 문자열로 반환
    4. refreshToken 생성: 빌더 -> 만료시간 설정 -> 토큰 서명 -> 문자열로 반환
    5. TokenInfo 반환
* public Authentiation getAuthentication(String accessToken)
  accessToekn을 기반으로 사용자의 정보를 가져오는 메소드
1. 토큰을 파싱해서 클레임 정보를 가져온다
2. “auth” 클레임에는 앞서 넣은 권한 정보들이 있다. 이를 추출해서 저장한다
3. UserDetails틀 통해 사용자 주체와 권한 정보를 담는다
4. 사용자 인증 정보(UsernamePasswordAuthe…)를 반환한다.

* public class JwtAuthenticationFilter
* doFilter
1. request 헤더에서 JWT 토큰을 추출한다.
2. 토큰의 유효성을 검사한다
3. 유효하면 인증 정보를 가져와서 SecuirtyContext에 저장한다.
4. 다음 필터로 간다
> 여기서 필터?
![ECEDB5BD-FF83-4CA5-86AD-C3701ACF6C03](https://github.com/BrownLEE99/tossaway/assets/137032025/c164899e-d911-4888-bd0f-3385358dc27f)

* 필터는 클라이언트의 요청을 가로채서 처리하고, 보안과 관련된 작업을 수행하며, 응답을 가공하여 클라이언트에게 반환하는 역할
* 우리가 만든 필터는 사용자의 토큰이 유효한지 확인하는 필터
---
### SecurityConfig
원래 WebSecurityConfiguerAdapter를 상속 받아 구현하는거지만 해당 과정은 deprecated 돼서 직접 SecurityConfig를 만들어야된다고 한다.
```java

@Configuration
@EnableWebSecurity // SpringSecurityFilterChain을 자동으로 포함
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement((sm)->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .httpBasic(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((auth) ->
                        auth
                                .requestMatchers("/members/login").permitAll()
                                .requestMatchers("/members/test").hasRole("USER")
                                .anyRequest().authenticated()
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider),UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}


```
* filterchain(HttpSecurity http)
1. csrf 끄기 : csrf().disable() -> deprecated , use AbstractHttpConfiguer::disable
2. 세션 관리 끄기
3. Basic auth 끄기
4. `/members/login` 에 대한 요청은 모두 허가
5. `/members/test/` 의 경우 권한이 `USER` 인 경우에만 허가
6. 그 외의 나머지 요청은 모두 인증을 필요로 한다(else 403 forbidden)
7. 위에 구현한 JWT 필터를 UsernamePassword인증필터 전에 실행
8. 비밀번호 인코더는 DelegatingPasswordEncoder를 사용
---
도메인을 생성하자
### Member
```java
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Member implements UserDetails {

    @Id
    @Column(updatable = false, unique = true,nullable = false)
    private String memberId;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @Builder.Default
    private List<String> roles = new ArrayList<>();


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return memberId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

```
* UserDetail은 User객체에 Authentication을 encapsulation 한 것.
---
### MemberRepository
```java
public interface MemberRepository extends JpaRepository<Member,Long> {
    Optional<Member> findByMemberId(String username);
}
```
* JpaRepository는 JPA를 사용하여 데이터베이스를 조작할 수 있는 메소드를 제공한다. 기본적인 CRUD인 findAll,findById,save 등의 메소드를 사용할 수 있다. 사용하려면 해당 리포지터리를 사용할 @Entitiy를 만들어놔야(Member)
---
### MemberService
```java
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public TokenInfo login(String memberId,String password) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberId, password);

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        return jwtTokenProvider.generateToken(authentication);
    }
}
```
1. memberId와 패스워드로 Authentication 객체를 생성한다
2. authenticate()를 통해 요청을 한 member를 검증한다
3. 검증이 통과되면 토큰을 발행한다.

2번에서 사용자 객체를 가져올 때 어떤 객체를 검증할 것인지에 대해 직접 구현해야 한다
---
### CustomUserDetailService
```java
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return memberRepository.findByMemberId(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException("해당 유저를 찾을 수 없습니다."));
    }

    private UserDetails createUserDetails(Member member) {
        return User.builder()
                .username(member.getUsername())
                .password(passwordEncoder.encode(member.getPassword()))
                .roles(member.getRoles().toArray(new String[0]))
                .build();
    }
}

```
* 위 코드는 Password를 인코딩해서 user객체를 반환하지만 실제로는 DB에 인코딩 된 Password를 가져와야한다.
---
### MemberController
이제 테스를 해보자
```java
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/login")
    public TokenInfo login(@RequestBody MemberLoginRequestDto memberLoginRequestDto) {
        String memberId = memberLoginRequestDto.getMemberId();
        String password = memberLoginRequestDto.getPassword();
        return memberService.login(memberId,password);
    }

    @PostMapping("/test")
    public String test() {
        System.out.println(SecurityUtil.getCurrentMemberId());
        return "success";
    }
}

// API 요청용 객체
@Data
public class MemberLoginRequestDto {
    private String memberId;
    private String password;
}
```
---
서버를 실행하고 디비도 실행해두자

디비에 테이블 만들어서 member_A,1234를 넣어두고

POSTMAN에서 테스트 해보자
![CA11807B-1BBF-4EBF-9E61-B709B1D866F2](https://github.com/BrownLEE99/tossaway/assets/137032025/17e03048-2127-4f16-9ccd-8a890252e6fc)


잘 나오는 것을 확인할 수 있다.

---
이번에는 받은 accessToken을 가지고 테스트해보자
![1AFEB9E2-0C57-4425-9C63-412CC6C6360E](https://github.com/BrownLEE99/tossaway/assets/137032025/d7d2a157-46f6-4776-9ff0-84ac436eb460)


참조 :
* [인증/인가Session(세션)과 Token(토큰)(JWT)의 차이점](https://fierycoding.tistory.com/69)
* [Spring Spring Security + JWT 토큰을 통한 로그인 — 오늘의 기록](https://gksdudrb922.tistory.com/217)
* [Getting Started | Spring Security Architecture](https://spring.io/guides/topicals/spring-security-architecture/)

