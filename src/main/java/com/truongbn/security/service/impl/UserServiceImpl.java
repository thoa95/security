package com.truongbn.security.service.impl;

import com.truongbn.security.entities.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.truongbn.security.repository.UserRepository;
import com.truongbn.security.service.UserService;

import lombok.RequiredArgsConstructor;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

    //@PreAuthorize
    //tạo proxy trước khi gọi method,
    // sau đó khi gọi hàm th nó kiểm tra role,
    // nếu đúng role = ADMIN thì hàm mới được thực thi
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getUsers(){
        log.info("In method get Users");
        return userRepository.findAll();
    }

    // @PostAuthorize: vẫn thực thi hàm nhưng không có Role =ADMIN
    // nên không return hay trả về kết quả được
    //tưc là có câu lệnh log trả ra nhưng không chayjh được đến return
    @PostAuthorize("returnObject.username == authentication.namme") //nếu username đăng nhập
    //bằng với username trong authen trả về thì hàm sẽ trả về kết quả
    public List<User> getUsers(String id){
        log.info("In method get Users By ID");
        return userRepository.findAll();
    }

    @Override
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) {
                return userRepository.findByEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            }
        };
    }
}
