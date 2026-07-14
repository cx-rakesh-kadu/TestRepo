/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.cysecurity.cspf.jvl.controller;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.undertow.server.protocol.http2.Http2UpgradeHandler;
import org.apache.coyote.ajp.AjpAprProtocol;
import io.undertow.server.protocol.ajp.*;
import org.apache.coyote.http11.Http11InputBuffer;
import org.apache.coyote.http2.Http2AsyncUpgradeHandler;
import org.json.JSONArray;

import java.io.*;

/**
 *
 * @author breakthesec
 */
public class AddPageVuln {


    public AddPageVuln() {
        AjpAprProtocol x = new AjpAprProtocol();
        x.setRequiredSecret("sdfdsf");
        AjpRequestParser t = new AjpRequestParser("a", true, 0, 0, false);
        t.parse(null, null, null);
        JSONArray jsonarray = new JSONArray(null);

    }


    private void runAnalysis()
    {
        Http11InputBuffer bufferParser = new Http11InputBuffer();
        bufferParser.parseHeaders();
        bufferParser.doRead();
        bufferParser.expand();
        bufferParser.getByteBuffer();
        new Http2AsyncUpgradeHandler();

    }
}
