// 파일명: scripts/main.js

Java.perform(function() {
    console.log("[Main] Frida script loaded. Waiting for initialization signal from Python.");

    // *** 변경점: Python에서 원격으로 호출할 진입점 함수 정의 ***
    rpc.exports.initializeHooks = function() {
        console.log("[Main] Initialization signal received. Loading modules...");
        
        // 1. 안티-탬퍼링 모듈 로드 및 실행
        const antiTamper = require('./utils/anti_tamper');
        antiTamper.bypass(); // require의 반환값으로 직접 호출
        
        // 2. 클래스로더 후킹 모듈 로드 및 실행
        const classLoaders = require('./hooks/classloaders');
        classLoaders.hook(); // require의 반환값으로 직접 호출

        console.log("[Main] All modules initialized and hooks are active.");
    };
});