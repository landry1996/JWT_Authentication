package org.sid.secservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sid.secservice.sec.JwtUtil;
import org.sid.secservice.sec.entities.AppRole;
import org.sid.secservice.sec.entities.AppUser;
import org.sid.secservice.sec.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

     private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }
    @GetMapping(path = "/users")
    @PostAuthorize("hasAnyAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.listUser();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAnyAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")

    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
       accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }
    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
          String auhToken = request.getHeader(JwtUtil.AUTH_HEADER);
          if (auhToken!=null && auhToken.startsWith(JwtUtil.PREFIX)){
              try {
                  String jwt = auhToken.substring(7);
                  Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
                  JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                  DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                  String username = decodedJWT.getSubject();
                  AppUser appUser = accountService.loadUserByUsername(username);
                  String jwtAccessToken = JWT.create()
                          .withSubject(appUser.getUsername())
                          .withExpiresAt(new Date(System.currentTimeMillis()+ JwtUtil.EXPIRE_ACCESS_TOKEN))
                          .withIssuer(request.getRequestURL().toString())
                          .withClaim("roles", appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                          .sign(algorithm);
                  Map<String,String> idToken = new HashMap<>();
                  idToken.put("access-token",jwtAccessToken);
                  idToken.put("refresh-token",jwt);
                  response.setContentType("application/json");

                  new ObjectMapper().writeValue(response.getOutputStream(),idToken);

              }
              catch (Exception e)
              {
                  throw e;
              }
          }
          else {
              throw new RuntimeException("Refresh Token required !!! ");
          }
    }

    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }

}


