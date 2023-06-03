package io.security.corespringsecurity.aopsecurity;

import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AopLiveMethodService {

    public void liveMethodSecured(){

        System.out.println("liveMethodSecured");
    }
}
