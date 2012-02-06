/**
 * Copyright Adrian Hayes 2012
 * 
 * This file is part of BurpJS.
 * BurpJS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * BurpJS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with BurpJS.  If not, see <http://www.gnu.org/licenses/>.
 */

package burp;

import java.io.IOException;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.EcmaError;

/**
 *
 * @author aj
 */
public class BurpExtender {

    private IBurpExtenderCallbacks burpCallback;


    private void onInit() {
        System.out.println("BurpJS Extension Loaded ( aj @ shinynightmares.com )");
        setupMenu();
    }  
    
    
    public synchronized void processHttpMessage(String toolName, boolean isRequest, IHttpRequestResponse message) {

        Context jsContext = Context.enter();
        try {

            JSEngine jsEngine = JSEngine.getInstance(burpCallback);

            if (isRequest) {

                HttpMessage request = jsEngine.buildHttpMessage(jsContext, burpCallback, isRequest, message);

                jsEngine.processRequest(jsContext, toolName, request);

                message.setRequest(request.getRawMessage());

            } else { //is response

                HttpMessage request = jsEngine.buildHttpMessage(jsContext, burpCallback, true, message);
                HttpMessage response = jsEngine.buildHttpMessage(jsContext, burpCallback, false, message, request.getUrl());

                jsEngine.processResponse(jsContext, toolName, request, response);

                message.setResponse(response.getRawMessage());
            }


        } catch (Exception ex) {

            String msg = "BurpJS Error (HTTP message will be unmodified by JS): " + ex.getMessage();

            burpCallback.issueAlert(msg);
            System.err.println(msg);

            if (ex instanceof EcmaError) {
                System.err.println(((EcmaError) ex).getScriptStackTrace());
            } else {
                ex.printStackTrace();
            }

        } finally {
            Context.exit();
        }
    }


    public void registerExtenderCallbacks(IBurpExtenderCallbacks burpCallback) {
        this.burpCallback = burpCallback;
        
        onInit();
    }

    private void setupMenu() {
        IMenuItemHandler menuHandler = new IMenuItemHandler() {

            @Override
            public void menuItemClicked(String menuCaption, IHttpRequestResponse[] ihrrs) {
                try {
                    JSEngine.getInstance(burpCallback).initDebugger();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        };
        
        
        burpCallback.registerMenuItem("Open JS Debugger", menuHandler);

    }
}
