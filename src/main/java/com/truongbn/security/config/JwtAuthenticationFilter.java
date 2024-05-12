package com.truongbn.security.config;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.truongbn.security.service.JwtService;
import com.truongbn.security.service.UserService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserService userService;
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, "Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        //lấy email từ token
        userEmail = jwtService.extractUserName(jwt);

        if (StringUtils.isNotEmpty(userEmail)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            //từ email lấy được tìm trong bảng user có tôn ftaij user nào có email đó hay không:
            UserDetails userDetails = userService.userDetailsService()
                    .loadUserByUsername(userEmail);
            //nếu userEmail từ token và trong DB khớp + Token chưa hết hạn:
            if (jwtService.isTokenValid(jwt, userDetails)) {

                //tạo đối tượng SecurityContext để chứa thông tin xác thực và ủy quyền của ng dùng:
                SecurityContext context = SecurityContextHolder.createEmptyContext();

                //Một đối tượng UsernamePasswordAuthenticationToken mới được tạo ra với userDetails,
                // null (không có mật khẩu được sử dụng trong trường hợp này),
                // và danh sách các quyền của người dùng
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                //Đối tượng WebAuthenticationDetails được tạo ra từ yêu cầu (request) hiện tại
                // và được đặt cho đối tượng authToken
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //Đối tượng authToken được đặt làm thông tin xác thực cho SecurityContext.
                context.setAuthentication(authToken);
                //thông tin xác thực sẽ được lưu trữ và quản lý trong suốt quá trình thực thi của luồng hiện tại của ứng dụng.
                SecurityContextHolder.setContext(context);
            }
        }
        filterChain.doFilter(request, response);//cho đi tiếp nếu thành công
    }
}
