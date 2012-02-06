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

import java.io.*;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.ContextFactory;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.tools.debugger.Main;

/**
 *
 * @author adrian
 */
public class JSEngine {
    
    private static final JSEngine INSTANCE = new JSEngine();
    
    private static final String JS_SOURCE_DIR = "javascript";
    private static final String REQUEST_FUNCTION = "processRequest";
    private static final String RESPONSE_FUNCTION = "processResponse";
    
    private Scriptable jsScope;
    private FileChangeMonitor fileMonitor;
    private boolean isStarted = false;
    private IBurpExtenderCallbacks burpCallback;
    private Main debuggerFrame;
    
    private JSEngine() {
        fileMonitor = new FileChangeMonitor();
    }
    
    public static JSEngine getInstance(IBurpExtenderCallbacks burpCallback) throws IOException {
        
        synchronized (INSTANCE) {
            if (!INSTANCE.isStarted){
                INSTANCE.setBurpCallback(burpCallback);
                INSTANCE.start();
            }
        }
        
        return INSTANCE;
    }
    
    private void start() throws IOException {

        addDirToJSMonitor(JS_SOURCE_DIR);
        
        restartEngine(); 
        
        isStarted = true;
                
    }
    
    public HttpMessage buildHttpMessage(Context jsContext, IBurpExtenderCallbacks burpCallback, boolean isRequest, IHttpRequestResponse burpMessage) throws Exception {
                
        String url = burpMessage.getUrl() == null ? null : burpMessage.getUrl().toString();
        return buildHttpMessage(jsContext, burpCallback, isRequest, burpMessage, url);
    }
    
    
    public HttpMessage buildHttpMessage(Context jsContext, IBurpExtenderCallbacks burpCallback, boolean isRequest, IHttpRequestResponse burpMessage, String url) throws Exception {
        
        byte[] rawMessage = isRequest ? burpMessage.getRequest() : burpMessage.getResponse();
        return new HttpMessage(jsContext, jsScope, burpCallback, isRequest, url, rawMessage);
    }

    
    public void processRequest(Context jsContext, String toolName, HttpMessage request) throws IOException {
        callProcessorFunction(jsContext, true, toolName, request, null);
    }

    public void processResponse(Context jsContext, String toolName, HttpMessage request, HttpMessage response) throws IOException {
        callProcessorFunction(jsContext, false, toolName, request, response);
    }
        
    private void callProcessorFunction(Context jsContext, boolean isRequest, String toolName, HttpMessage request, HttpMessage response) throws IOException {
        checkForSourceUpdate();
        
        String functionName;  
        Object args[];
        if (isRequest) {    
            functionName = REQUEST_FUNCTION;
            args = new Object[] { toolName, request };
        } else {
            functionName = RESPONSE_FUNCTION;
            args = new Object[] { toolName, request, response };
        }
        
        Object funcObj = jsScope.get(functionName, jsScope);
        if (funcObj == Scriptable.NOT_FOUND)
            throw new RuntimeException("Required JS function not found in source (or script eval failed, probably syntax errors): " + functionName);
      
        Function func = (Function)funcObj;

        func.call(jsContext, jsScope, func, args);
        
    }
    
    
    
    void setBurpCallback(IBurpExtenderCallbacks burpCallback) {
        this.burpCallback = burpCallback;
    }
    
    
    private void addDirToJSMonitor(String dirPath) throws IOException {
        File dir = new File(dirPath);
        if (!dir.exists() || !dir.isDirectory())
            throw new IOException("JS source directory not found: " + dir.getAbsolutePath());
        
        for (File file : dir.listFiles()) {
            if (!file.getName().toLowerCase().endsWith("js"))
                continue;
            
            fileMonitor.addFile(file);
            
            System.out.println("Loaded JS source file: " + file.getName());
        }
    }
    
    
    private void checkForSourceUpdate() throws IOException {
        if (fileMonitor.hasAnyFileChanged())
            restartEngine();
    }
        
    private void restartEngine() throws IOException {
        
        System.out.println("Starting BurpJS Engine");
        
        fileMonitor.resetAll();
                
        Context cx = Context.enter();
        try {
                    
            jsScope = cx.initStandardObjects();
            
            for (File file : fileMonitor.getMonitoredFiles())
                evalSourceFile(cx, file);
            
            addBurpInterface(jsScope);
             
        } finally {
            Context.exit();
        }
        
    }
    
    private void evalSourceFile(Context cx, File sourceFile) throws IOException {
        Reader fileReader = new InputStreamReader(new FileInputStream(sourceFile));
        cx.evaluateReader(jsScope, fileReader, sourceFile.getName(), 1, null);
        fileReader.close();  
    }

    private void addBurpInterface(Scriptable jsScope) {
        Object funcObj = jsScope.get("setBurpInterface", jsScope);
        if (funcObj == Scriptable.NOT_FOUND) {
            System.err.println("BurpJS: Cannot add Burp Interface, function not found in JS source");
            return;
        }        
        
        Object args[] = { burpCallback };
        Function func = (Function)funcObj;
        
        Context cx = Context.enter();
        try {
            func.call(cx, jsScope, func, args);
        } finally {
            Context.exit();
        }
               
    }
    
    
    public void initDebugger() throws IOException {

        if (debuggerFrame == null) {

            debuggerFrame = Main.mainEmbedded(ContextFactory.getGlobal(), jsScope, "Burp JS Debugger");
            debuggerFrame.setSize(900, 600);
            debuggerFrame.setExitAction(new Runnable() {

                @Override
                public void run() {
                    debuggerFrame.setVisible(false);
                    debuggerFrame.detach();
                    debuggerFrame.dispose();
                    debuggerFrame = null;
                }
            });
            
            
            restartEngine();

        }

    }
}
