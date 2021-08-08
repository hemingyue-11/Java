# 结合SpringSecurity实现接口的动态权限管理

ums_resource: 后台资源表，用于控制后台用户可以访问的接口，使用了Ant路径的匹配规则，可以使用通配符定义一系列接口的权限



* 首先我们需要创建一个过滤器，用于实现动态权限控制，这里需要注意的是`doFilter`方法，对于OPTIONS请求直接放行，否则前端调用会出现跨域问题。对于配置在`IgnoreUrlsConfig`中的白名单路径我也需要直接放行，所有的鉴权操作都会在`super.beforeInvocation(fi)`中进行。

  ```java
  public class DynamicSecurityFilter extends AbstractSecurityInterceptor implements Filter {
  
      @Autowired
      private DynamicSecurityMetadataSource dynamicSecurityMetadataSource;
      @Autowired
      private IgnoreUrlsConfig ignoreUrlsConfig;
  
      @Autowired
      public void setMyAccessDecisionManager(DynamicAccessDecisionManager dynamicAccessDecisionManager) {
          super.setAccessDecisionManager(dynamicAccessDecisionManager);
      }
  
      @Override
      public void init(FilterConfig filterConfig) throws ServletException {
      }
  
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
          HttpServletRequest request = (HttpServletRequest) servletRequest;
          FilterInvocation fi = new FilterInvocation(servletRequest, servletResponse, filterChain);
          //OPTIONS请求直接放行
          if(request.getMethod().equals(HttpMethod.OPTIONS.toString())){
              fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
              return;
          }
          //白名单请求直接放行
          PathMatcher pathMatcher = new AntPathMatcher();
          for (String path : ignoreUrlsConfig.getUrls()) {
              if(pathMatcher.match(path,request.getRequestURI())){
                  fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
                  return;
              }
          }
          //此处会调用AccessDecisionManager中的decide方法进行鉴权操作
          InterceptorStatusToken token = super.beforeInvocation(fi);
          try {
              fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
          } finally {
              super.afterInvocation(token, null);
          }
      }
  
      @Override
      public void destroy() {
      }
  
      @Override
      public Class<?> getSecureObjectClass() {
          return FilterInvocation.class;
      }
  
      @Override
      public SecurityMetadataSource obtainSecurityMetadataSource() {
          return dynamicSecurityMetadataSource;
      }
  
  }
  
  ```

* ```java
  /**
   * 动态权限过滤器，用于实现基于路径的动态权限过滤
   * Created by macro on 2020/2/7.
   */
  public class DynamicSecurityFilter extends AbstractSecurityInterceptor implements Filter {
  
      @Autowired
      private DynamicSecurityMetadataSource dynamicSecurityMetadataSource;
      @Autowired
      private IgnoreUrlsConfig ignoreUrlsConfig;
  
      @Autowired
      public void setMyAccessDecisionManager(DynamicAccessDecisionManager dynamicAccessDecisionManager) {
          super.setAccessDecisionManager(dynamicAccessDecisionManager);
      }
  
      @Override
      public void init(FilterConfig filterConfig) throws ServletException {
      }
  
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
          HttpServletRequest request = (HttpServletRequest) servletRequest;
          FilterInvocation fi = new FilterInvocation(servletRequest, servletResponse, filterChain);
          //OPTIONS请求直接放行
          if(request.getMethod().equals(HttpMethod.OPTIONS.toString())){
              fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
              return;
          }
          //白名单请求直接放行
          PathMatcher pathMatcher = new AntPathMatcher();
          for (String path : ignoreUrlsConfig.getUrls()) {
              if(pathMatcher.match(path,request.getRequestURI())){
                  fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
                  return;
              }
          }
          //此处会调用AccessDecisionManager中的decide方法进行鉴权操作
          InterceptorStatusToken token = super.beforeInvocation(fi);
          try {
              fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
          } finally {
              super.afterInvocation(token, null);
          }
      }
  
      @Override
      public void destroy() {
      }
  
      @Override
      public Class<?> getSecureObjectClass() {
          return FilterInvocation.class;
      }
  
      @Override
      public SecurityMetadataSource obtainSecurityMetadataSource() {
          return dynamicSecurityMetadataSource;
      }
  
  }
  ```

* 在DynamicSecurityFilter中调用super.beforeInvocation(fi)方法时会调用AccessDecisionManager中的decide方法用于鉴权操作，而decide方法中的configAttributes参数会通过SecurityMetadataSource中的getAttributes方法来获取，configAttributes其实就是配置好的访问当前接口所需要的权限，下面是简化版的beforeInvocation源码。

  ```java
  public abstract class AbstractSecurityInterceptor implements InitializingBean,
          ApplicationEventPublisherAware, MessageSourceAware {
  
  
  protected InterceptorStatusToken beforeInvocation(Object object) {
  
          //获取元数据(访问当前接口所需要的权限)
          Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource()
                  .getAttributes(object);
  
      	//当前访问的用户有的权限
          Authentication authenticated = authenticateIfRequired();
  
          //进行鉴权操作
          try {
              //通过比较当前接口所需要的权限以及用户拥有的权限，判断是否有权限访问该接口
              this.accessDecisionManager.decide(authenticated, object, attributes);
          }
          catch (AccessDeniedException accessDeniedException) {
              publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated,
                      accessDeniedException));
  
              throw accessDeniedException;
          }
      }
  }
  
  ```

* 首先我们要获得访问当前接口所需要的权限，我们需要自己实现SecurityMetadataSource接口的getAttributes方法，用于获取当前访问路径所需资源。

  ```java
  /**
   * 动态权限数据源，用于获取动态权限规则
   * Created by macro on 2020/2/7.
   */
  public class DynamicSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
  
      private static Map<String, ConfigAttribute> configAttributeMap = null;
      @Autowired
      private DynamicSecurityService dynamicSecurityService;
  
      //通过dynamicSecurityService（需要自己实现）来加载所有的资源
      @PostConstruct
      public void loadDataSource() {
          configAttributeMap = dynamicSecurityService.loadDataSource();
      }
  
      public void clearDataSource() {
          configAttributeMap.clear();
          configAttributeMap = null;
      }
  
      @Override
      public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
    	    //通过dynamicSecurityService（需要自己实现）来加载所有的资源
          if (configAttributeMap == null) this.loadDataSource();
          List<ConfigAttribute>  configAttributes = new ArrayList<>();
          //获取当前访问的路径
          String url = ((FilterInvocation) o).getRequestUrl();
          String path = URLUtil.getPath(url);
          PathMatcher pathMatcher = new AntPathMatcher();
          Iterator<String> iterator = configAttributeMap.keySet().iterator();
          //获取访问该路径所需资源
          while (iterator.hasNext()) {
              String pattern = iterator.next();
              //如果当前路径和资源路径匹配就添加到返回集合中。
              if (pathMatcher.match(pattern, path)) {
                  configAttributes.add(configAttributeMap.get(pattern));
              }
          }
          // 未设置操作请求权限，返回空集合
          return configAttributes;
      }
  
      @Override
      public Collection<ConfigAttribute> getAllConfigAttributes() {
          return null;
      }
  
      @Override
      public boolean supports(Class<?> aClass) {
          return true;
      }
  
  }
  
  ```

  由于我们的后台资源规则被缓存在了一个Map对象之中，所以当后台资源发生变化时，我们需要清空缓存的数据，然后下次查询时就会被重新加载进来。这里我们需要修改UmsResourceController类，注入DynamicSecurityMetadataSource，当修改后台资源时，需要调用clearDataSource方法来清空缓存的数据。

  ```java
  /**
   * 动态权限决策管理器，用于判断用户是否有访问权限
   * Created by macro on 2020/2/7.
   */
  public class DynamicAccessDecisionManager implements AccessDecisionManager {
  
      @Override
      public void decide(Authentication authentication, Object object,
                         Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
          // 当接口未被配置资源时直接放行
          if (CollUtil.isEmpty(configAttributes)) {
              return;
          }
          Iterator<ConfigAttribute> iterator = configAttributes.iterator();
          while (iterator.hasNext()) {
              ConfigAttribute configAttribute = iterator.next();
              //将访问所需资源或用户拥有资源进行比对
              String needAuthority = configAttribute.getAttribute();
              for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
                  if (needAuthority.trim().equals(grantedAuthority.getAuthority())) {
                      return;
                  }
              }
          }
          throw new AccessDeniedException("抱歉，您没有访问权限");
      }
  
      @Override
      public boolean supports(ConfigAttribute configAttribute) {
          return true;
      }
  
      @Override
      public boolean supports(Class<?> aClass) {
          return true;
      }
  
  }
  ```

* 之后我们需要实现AccessDecisionManager接口来实现权限校验，对于没有配置资源的接口我们直接允许访问，对于配置了资源的接口，我们把访问所需资源和用户拥有的资源进行比对，如果匹配则允许访问。

  ```java
  /**
   * 动态权限决策管理器，用于判断用户是否有访问权限
   * Created by macro on 2020/2/7.
   */
  public class DynamicAccessDecisionManager implements AccessDecisionManager {
  
      //authentication: 当前用户拥有的权限
      //configAttributes：访问当前接口需要的权限
      @Override
      public void decide(Authentication authentication, Object object,
                         Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
          // 当接口未被配置资源时直接放行
          if (CollUtil.isEmpty(configAttributes)) {
              return;
          }
          Iterator<ConfigAttribute> iterator = configAttributes.iterator();
          while (iterator.hasNext()) {
              ConfigAttribute configAttribute = iterator.next();
              //将访问所需资源或用户拥有资源进行比对
              String needAuthority = configAttribute.getAttribute();
              for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
                  if (needAuthority.trim().equals(grantedAuthority.getAuthority())) {
                      return;
                  }
              }
          }
          throw new AccessDeniedException("抱歉，您没有访问权限");
      }
  
      @Override
      public boolean supports(ConfigAttribute configAttribute) {
          return true;
      }
  
      @Override
      public boolean supports(Class<?> aClass) {
          return true;
      }
  
  }
  ```

* 我们之前在DynamicSecurityMetadataSource中注入了一个DynamicSecurityService对象，它是我自定义的一个动态权限业务接口，其主要用于加载所有的后台资源规则。

  ```java
  /**
   * 动态权限相关业务类
   * Created by macro on 2020/2/7.
   */
  public interface DynamicSecurityService {
      /**
       * 加载资源ANT通配符和资源对应MAP
       */
      Map<String, ConfigAttribute> loadDataSource();
  }
  ```

* 接下来我们需要修改Spring Security的配置类SecurityConfig，当有动态权限业务类时在FilterSecurityInterceptor过滤器前添加我们的动态权限过滤器。这里在创建动态权限相关对象时，还使用了@ConditionalOnBean这个注解，当没有动态权限业务类时就不会创建动态权限相关对象，实现了有动态权限控制和没有这两种情况的兼容。

  ```java
  /**
   * 对SpringSecurity的配置的扩展，支持自定义白名单资源路径和查询用户逻辑
   * Created by macro on 2019/11/5.
   */
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
  
      @Autowired(required = false)
      private DynamicSecurityService dynamicSecurityService;
  
      @Override
      protected void configure(HttpSecurity httpSecurity) throws Exception {
          ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry = httpSecurity
                  .authorizeRequests();
          //有动态权限配置时添加动态权限校验过滤器
          if(dynamicSecurityService!=null){
              registry.and().addFilterBefore(dynamicSecurityFilter(), FilterSecurityInterceptor.class);
          }
      }
  
      @ConditionalOnBean(name = "dynamicSecurityService")
      @Bean
      public DynamicAccessDecisionManager dynamicAccessDecisionManager() {
          return new DynamicAccessDecisionManager();
      }
  
  
      @ConditionalOnBean(name = "dynamicSecurityService")
      @Bean
      public DynamicSecurityFilter dynamicSecurityFilter() {
          return new DynamicSecurityFilter();
      }
  
      @ConditionalOnBean(name = "dynamicSecurityService")
      @Bean
      public DynamicSecurityMetadataSource dynamicSecurityMetadataSource() {
          return new DynamicSecurityMetadataSource();
      }
  
  }
  ```

* 这里还有个问题需要提下，当前端跨域访问没有权限的接口时，会出现跨域问题，只需要在没有权限访问的处理类RestfulAccessDeniedHandler中添加允许跨域访问的响应头即可。

  ```java
  /**
   * 自定义返回结果：没有权限访问时
   * Created by macro on 2018/4/26.
   */
  public class RestfulAccessDeniedHandler implements AccessDeniedHandler{
      @Override
      public void handle(HttpServletRequest request,
                         HttpServletResponse response,
                         AccessDeniedException e) throws IOException, ServletException {
          response.setHeader("Access-Control-Allow-Origin", "*");
          response.setHeader("Cache-Control","no-cache");
          response.setCharacterEncoding("UTF-8");
          response.setContentType("application/json");
          response.getWriter().println(JSONUtil.parse(CommonResult.forbidden(e.getMessage())));
          response.getWriter().flush();
      }
  }
  ```

* 当我们其他模块需要动态权限控制时，只要创建一个DynamicSecurityService对象就行了，比如在`mall-admin`模块中我们启用了动态权限功能。

  ```java
  /**
   * mall-security模块相关配置
   * Created by macro on 2019/11/9.
   */
  @Configuration
  @EnableWebSecurity
  @EnableGlobalMethodSecurity(prePostEnabled = true)
  public class MallSecurityConfig extends SecurityConfig {
  
      @Autowired
      private UmsAdminService adminService;
      @Autowired
      private UmsResourceService resourceService;
  
      @Bean
      public UserDetailsService userDetailsService() {
          //获取登录用户信息
          return username -> adminService.loadUserByUsername(username);
      }
  
      @Bean
      public DynamicSecurityService dynamicSecurityService() {
          return new DynamicSecurityService() {
              @Override
              public Map<String, ConfigAttribute> loadDataSource() {
                  Map<String, ConfigAttribute> map = new ConcurrentHashMap<>();
                  List<UmsResource> resourceList = resourceService.listAll();
                  for (UmsResource resource : resourceList) {
                      map.put(resource.getUrl(), new org.springframework.security.access.SecurityConfig(resource.getId() + ":" + resource.getName()));
                  }
                  return map;
              }
          };
      }
  }
  ```