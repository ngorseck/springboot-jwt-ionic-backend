package org.sid.sercurityservice.security.util;

public class JwtUtils {

    public static final String SECRET = "mySecret1234";
    public static final String AUTH_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRE_ACCESS_TOKEN = 2*60*100; //chaque 2 minutes
    public static final long EXPIRE_REFRESH_TOKEN = 1560000;//15*60*100; //chaque 2 minutes

}
