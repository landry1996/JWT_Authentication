package org.sid.secservice.sec;

public class JwtUtil {
    public static final String SECRET = "monSecret1234";
    public static final String AUTH_HEADER = "authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 2*60*1000;
    public static final long EXPIRE_REFRESH_TOKEN = 15*60*1000;
}
