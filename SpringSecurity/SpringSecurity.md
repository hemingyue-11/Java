# SpringSecurity实现认证和授权

# * 登录认证：

```java
    @Override
    public String login(String username, String password) {
        String token = null;
        try {
     		//首先获取userDetails（通过查询数据库）
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            //比较数据库中查询的用户信息和用户输入的用户信息是否相等
            if (!passwordEncoder.matches(password, userDetails.getPassword())) {
                throw new BadCredentialsException("密码不正确");
            }
            //如果相等就把userDetails以及用户的权限包装成Token放入到Security容器中来进行权限认证。
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            //生成jwt并返回给客户端。
            token = jwtTokenUtil.generateToken(userDetails);
        } catch (AuthenticationException e) {
            LOGGER.warn("登录异常:{}", e.getMessage());
        }
        return token;
    }
```





* SpringSecurity定义的核心接口，用于根据用户名获取用户信息，需要自行实现。

  ```java
  	@Bean
      public UserDetailsService userDetailsService() {
          //获取登录用户信息
          return username -> {
              //查询数据库获得用户信息
              UmsAdmin admin = adminService.getAdminByUsername(username);
              if (admin != null) {
                  //如果查到了用户信息，接着获取权限信息并包装成UserDetails返回。
                  List<UmsPermission> permissionList = adminService.getPermissionList(admin.getId());
                  return new AdminUserDetails(admin,permissionList);
              }
              throw new UsernameNotFoundException("用户名或密码错误");
          };
      }
  ```

  

* 服务端继承UserDetails并重写getAuthorities()用于封装用户信息类，主要是用户信息和权限信息，需要自行实现。

  ```java
  public class AdminUserDetails implements UserDetails {
      private UmsAdmin umsAdmin;
      private List<UmsPermission> permissionList;
      public AdminUserDetails(UmsAdmin umsAdmin, List<UmsPermission> permissionList) {
          this.umsAdmin = umsAdmin;
          this.permissionList = permissionList;
      }
  
      //返回的权限需要实现GrantedAuthority接口
      @Override
      public Collection<? extends GrantedAuthority> getAuthorities() {
          //返回当前用户的权限
          return permissionList.stream()
                  .filter(permission -> permission.getValue()!=null)
                  .map(permission ->new SimpleGrantedAuthority(permission.getValue()))
                  .collect(Collectors.toList());
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
          return umsAdmin.getStatus().equals(1);
      }
  }
  
  ```

* 添加SpringSecurity的配置类

  ```java
  @Configuration
  @EnableWebSecurity
  @EnableGlobalMethodSecurity(prePostEnabled=true)
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
      @Autowired
      private UmsAdminService adminService;
      
      //当用户没有权限访问是的处理器，用于返回JSON的处理结果
      @Autowired
      private RestfulAccessDeniedHandler restfulAccessDeniedHandler;
      
      //当未登录或token失效时返回JSON的处理结果
      @Autowired
      private RestAuthenticationEntryPoint restAuthenticationEntryPoint;
  
      //用与配置需要拦截的路径，jwt过滤器以及异常处理器
      @Override
      protected void configure(HttpSecurity httpSecurity) throws Exception {
          httpSecurity.csrf()// 由于使用的是JWT，我们这里不需要csrf
                  .disable()
                  .sessionManagement()// 基于token，所以不需要session
                  .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                  .and()
                  .authorizeRequests()
                  .antMatchers(HttpMethod.GET, // 允许对于网站静态资源的无授权访问
                          "/",
                          "/*.html",
                          "/favicon.ico",
                          "/**/*.html",
                          "/**/*.css",
                          "/**/*.js",
                          "/swagger-resources/**",
                          "/v2/api-docs/**"
                  )
                  .permitAll()
                  .antMatchers("/admin/login", "/admin/register")// 对登录注册要允许匿名访问
                  .permitAll()
                  .antMatchers(HttpMethod.OPTIONS)//跨域请求会先进行一次options请求
                  .permitAll()
  //                .antMatchers("/**")//测试时全部运行访问
  //                .permitAll()
                  .anyRequest()// 除上面外的所有请求全部需要鉴权认证
                  .authenticated();
          // 禁用缓存
          httpSecurity.headers().cacheControl();
          // 添加JWT filter
          httpSecurity.addFilterBefore(jwtAuthenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);
          //添加自定义未授权和未登录结果返回
          httpSecurity.exceptionHandling()
                  .accessDeniedHandler(restfulAccessDeniedHandler)
                  .authenticationEntryPoint(restAuthenticationEntryPoint);
      }
  
      //用域配置UseDetails及PasswordEncoder
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          auth.userDetailsService(userDetailsService())
                  .passwordEncoder(passwordEncoder());
      }
  
      //SpringSecurity用于对密码进行编码及对比的接口，
      @Bean
      public PasswordEncoder passwordEncoder() {
          return new BCryptPasswordEncoder();
      }
  
      @Bean
      public UserDetailsService userDetailsService() {
          //获取登录用户信息
          return username -> {
              UmsAdmin admin = adminService.getAdminByUsername(username);
              if (admin != null) {
                  List<UmsPermission> permissionList = adminService.getPermissionList(admin.getId());
                  return new AdminUserDetails(admin,permissionList);
              }
              throw new UsernameNotFoundException("用户名或密码错误");
          };
      }
  
      //在用户名和密码验证前添加的过滤器，如果请求头由jwt的token，会自行根据token信息进行登录。
      @Bean
      public JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter(){
          return new JwtAuthenticationTokenFilter();
      }
  
      @Bean
      @Override
      public AuthenticationManager authenticationManagerBean() throws Exception {
          return super.authenticationManagerBean();
      }
  
  }
  ```

* 添加JwtAuthenticationTokenFilter

  在用户名和密码校验前添加的过滤器，如果请求中有jwt的token并且有效，会取出token中的用户名，然后调用SpringSecurity的API进行登陆操作。

  ```java
  public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
      private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);
      @Autowired
      private UserDetailsService userDetailsService;
      @Autowired
      private JwtTokenUtil jwtTokenUtil;
      @Value("${jwt.tokenHeader}")
      private String tokenHeader;
      @Value("${jwt.tokenHead}")
      private String tokenHead;
  
      @Override
      protected void doFilterInternal(HttpServletRequest request,
                                      HttpServletResponse response,
                                      FilterChain chain) throws ServletException, IOException {
          String authHeader = request.getHeader(this.tokenHeader);
          if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
              //从请求的Header中取出token
              String authToken = authHeader.substring(this.tokenHead.length());// The part after "Bearer "
              //从token中解析出用户名
              String username = jwtTokenUtil.getUserNameFromToken(authToken);
              LOGGER.info("checking username:{}", username);
              if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                  //根据解析出的用户名从是数据库中查到用户信息
                  UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                  //验证token是否有效
                  if (jwtTokenUtil.validateToken(authToken, userDetails)) {
                      //将用户的权限信息存入到Security容器中
                      UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                      authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                      LOGGER.info("authenticated user:{}", username);
                      SecurityContextHolder.getContext().setAuthentication(authentication);
                  }
              }
          }
          chain.doFilter(request, response);
      }
  }
  
  ```

* 登录注册功能实现

  ```java
  //后台用户登录、注册及获取权限的接口
  @Controller
  @Api(tags = "UmsAdminController", description = "后台用户管理")
  @RequestMapping("/admin")
  public class UmsAdminController {
      @Autowired
      private UmsAdminService adminService;
      @Value("${jwt.tokenHeader}")
      private String tokenHeader;
      @Value("${jwt.tokenHead}")
      private String tokenHead;
  
      @ApiOperation(value = "用户注册")
      @RequestMapping(value = "/register", method = RequestMethod.POST)
      @ResponseBody
      public CommonResult<UmsAdmin> register(@RequestBody UmsAdmin umsAdminParam, BindingResult result) {
          UmsAdmin umsAdmin = adminService.register(umsAdminParam);
          if (umsAdmin == null) {
              CommonResult.failed();
          }
          return CommonResult.success(umsAdmin);
      }
  
      @ApiOperation(value = "登录以后返回token")
      @RequestMapping(value = "/login", method = RequestMethod.POST)
      @ResponseBody
      public CommonResult login(@RequestBody UmsAdminLoginParam umsAdminLoginParam, BindingResult result) {
          String token = adminService.login(umsAdminLoginParam.getUsername(), umsAdminLoginParam.getPassword());
          if (token == null) {
              return CommonResult.validateFailed("用户名或密码错误");
          }
          Map<String, String> tokenMap = new HashMap<>();
          tokenMap.put("token", token);
          tokenMap.put("tokenHead", tokenHead);
          return CommonResult.success(tokenMap);
      }
  
      @ApiOperation("获取用户所有权限（包括+-权限）")
      @RequestMapping(value = "/permission/{adminId}", method = RequestMethod.GET)
      @ResponseBody
      public CommonResult<List<UmsPermission>> getPermissionList(@PathVariable Long adminId) {
          List<UmsPermission> permissionList = adminService.getPermissionList(adminId);
          return CommonResult.success(permissionList);
      }
  }
  
  ```

* 添加UmsAdminService接口

  ```java
  
  public interface UmsAdminService {
      /**
       * 根据用户名获取后台管理员
       */
      UmsAdmin getAdminByUsername(String username);
  
      /**
       * 注册功能
       */
      UmsAdmin register(UmsAdmin umsAdminParam);
  
      /**
       * 登录功能
       * @param username 用户名
       * @param password 密码
       * @return 生成的JWT的token
       */
      String login(String username, String password);
  
      /**
       * 获取用户所有权限（包括角色权限和+-权限）
       */
      List<UmsPermission> getPermissionList(Long adminId);
  }
  
  ```

* 添加UmsAdminServiceImpl类

  ```java
  
  @Service
  public class UmsAdminServiceImpl implements UmsAdminService {
      private static final Logger LOGGER = LoggerFactory.getLogger(UmsAdminServiceImpl.class);
      @Autowired
      private UserDetailsService userDetailsService;
      @Autowired
      private JwtTokenUtil jwtTokenUtil;
      @Autowired
      private PasswordEncoder passwordEncoder;
      @Value("${jwt.tokenHead}")
      private String tokenHead;
      @Autowired
      private UmsAdminMapper adminMapper;
      @Autowired
      private UmsAdminRoleRelationDao adminRoleRelationDao;
  
      //通过用户名从数据库中查到用户信息
      @Override
      public UmsAdmin getAdminByUsername(String username) {
          UmsAdminExample example = new UmsAdminExample();
          example.createCriteria().andUsernameEqualTo(username);
          List<UmsAdmin> adminList = adminMapper.selectByExample(example);
          if (adminList != null && adminList.size() > 0) {
              return adminList.get(0);
          }
          return null;
      }
  
      
      @Override
      public UmsAdmin register(UmsAdmin umsAdminParam) {
          UmsAdmin umsAdmin = new UmsAdmin();
          BeanUtils.copyProperties(umsAdminParam, umsAdmin);
          umsAdmin.setCreateTime(new Date());
          umsAdmin.setStatus(1);
          //查询是否有相同用户名的用户
          UmsAdminExample example = new UmsAdminExample();
          example.createCriteria().andUsernameEqualTo(umsAdmin.getUsername());
          List<UmsAdmin> umsAdminList = adminMapper.selectByExample(example);
          if (umsAdminList.size() > 0) {
              return null;
          }
          //将密码进行加密操作
          String encodePassword = passwordEncoder.encode(umsAdmin.getPassword());
          umsAdmin.setPassword(encodePassword);
          adminMapper.insert(umsAdmin);
          return umsAdmin;
      }
  
      
      @Override
      public String login(String username, String password) {
          String token = null;
          try {
              //根据用户输入的用户名从数据库中查到用户信息
              UserDetails userDetails = userDetailsService.loadUserByUsername(username);
              //判断用户输入的用户信息是否正确
              if (!passwordEncoder.matches(password, userDetails.getPassword())) {
                  throw new BadCredentialsException("密码不正确");
              }
              //如果正确就将用户的权限信息设置到Security容器中
              UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
              SecurityContextHolder.getContext().setAuthentication(authentication);
              //生成token信息并返回g
              token = jwtTokenUtil.generateToken(userDetails);
          } catch (AuthenticationException e) {
              LOGGER.warn("登录异常:{}", e.getMessage());
          }
          return token;
      }
  
  
      @Override
      public List<UmsPermission> getPermissionList(Long adminId) {
          return adminRoleRelationDao.getPermissionList(adminId);
      }
  }
  
  ```

  