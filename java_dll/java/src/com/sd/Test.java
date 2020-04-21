package com.sd;

import hello.HelloLibrary;

import java.io.UnsupportedEncodingException;

public class Test {
    public static void add() throws UnsupportedEncodingException {
        // write your code here
        int re = HelloLibrary.INSTANCE.add(2, 3);
        System.out.println("initInstance return "+re);
    }
}