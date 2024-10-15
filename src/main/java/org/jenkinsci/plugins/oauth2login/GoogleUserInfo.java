/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.oauth2login;

import java.io.IOException;

import com.google.api.client.util.Key;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.tasks.Mailer;

/**
 * 表示来自oauth提供者的身份信息。
 *
 * 这是从类似 https://example.com/userinfo 获取的
 */
public class GoogleUserInfo extends UserProperty {

    @Key("code")
    public int code;

    @Key("msg")
    public String msg;

    @Key("name")
    private String name;

    @Key("email")
    private String email;

    @Key("data")
    private Data data;

    public static class Data {
        @Key("name")
        public String name;
    
        @Key("email")
        public String email;
    }

    public String getEmail() {
        if (email != null) {
            return email;
        }
        return data != null ? data.email : null;
    }

    public String getName() {
        if (name != null) {
            return name;
        }
        return data != null ? data.name : null;
    }

    public boolean hasError() {
        return code != 0 && code != 200;
    }
    
    public String getErrorMessage() {
        return msg;
    }

    /**
     * 根据此身份信息更新用户。
     */
    public void updateProfile(hudson.model.User u) throws IOException {
        String email = getEmail();
        String name = getName();
        
        if (email != null)
            u.addProperty(new Mailer.UserProperty(email));

        if (name != null)
            u.setFullName(name);

        u.addProperty(this);
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }

        @Override
        public boolean isEnabled() {
            return false;
        }
    }
}
