package org.tonyzampogna.xss.sanitizer.util;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class XssSanitizerUtilTest {
    @BeforeClass
    public static void setEsapiResources() {
        System.setProperty("org.owasp.esapi.resources", "grails-app/conf");
    }

    @AfterClass
    public static void unsetEsapiResources() {
        System.clearProperty("org.owasp.esapi.resources");
    }

    @Test
    public void shouldStripOutNullCharacters() {
        final String output = XssSanitizerUtil.stripXSS("\0");
        assertThat(output, is("&#xfffd;"));
    }

    @Test
    public void shouldStripOutContentOfScriptTags() {
        final String output = XssSanitizerUtil.stripXSS("valid-content<script>xss-content</script>");
        assertThat(output, is("valid-content&lt;script&gt;xss-content&lt;&#x2f;script&gt;"));
    }

    @Test
    public void shouldStripOutTrailingScriptTag() {
        final String output = XssSanitizerUtil.stripXSS("</script>valid-content");
        assertThat(output, is("&lt;&#x2f;script&gt;valid-content"));
    }

    @Test
    public void shouldStripOutStartingScriptTag() {
        final String output = XssSanitizerUtil.stripXSS("<script src='xss.js'>valid-content");
        assertThat(output, is("&lt;script&#x20;src&#x3d;&#x27;xss.js&#x27;&gt;valid-content"));
    }

    @Test
    public void shouldStripOutEvalAttribute() {
        final String output = XssSanitizerUtil.stripXSS("eval('xss-js-content')");
        assertThat(output, is("eval&#x28;&#x27;xss-js-content&#x27;&#x29;"));
    }

    @Test
    public void shouldStripOutExpressionAttribute() {
        final String output = XssSanitizerUtil.stripXSS("expression('xss-content')");
        assertThat(output, is("expression&#x28;&#x27;xss-content&#x27;&#x29;"));
    }

    @Test
    public void shouldStripOutOnloadAttribute() {
        final String output = XssSanitizerUtil.stripXSS("onload=xss.execute()");
        assertThat(output, is("onload&#x3d;xss.execute&#x28;&#x29;"));
    }

    @Test
    public void shouldStripOutJavascriptProtocol() {
        final String output = XssSanitizerUtil.stripXSS("javascript:xss.execute()");
        assertThat(output, is("javascript&#x3a;xss.execute&#x28;&#x29;"));
    }

    @Test
    public void shouldStripOutVbcriptProtocol() {
        final String output = XssSanitizerUtil.stripXSS("vbscript:xss.execute()");
        assertThat(output, is("vbscript&#x3a;xss.execute&#x28;&#x29;"));
    }

    @Test
    public void shouldStripOutSrcAttribute() {
        final String output = XssSanitizerUtil.stripXSS("<img src='xss.jpg'>");
        assertThat(output, is("&lt;img&#x20;src&#x3d;&#x27;xss.jpg&#x27;&gt;"));
    }

    @Test
    public void shouldStripOutContentOfIframeTags() {
        final String output = XssSanitizerUtil.stripXSS("<iframe src='xss.html'>xss-content</iframe>");
        assertThat(output, is("&lt;iframe&#x20;src&#x3d;&#x27;xss.html&#x27;&gt;xss-content&lt;&#x2f;iframe&gt;"));
    }

    @Test
    public void shouldStripOutContentOfForm() {
        final String output = XssSanitizerUtil.stripXSS("<form action=''><input id='formInjection'></form>");
        assertThat(output, is("&lt;form&#x20;action&#x3d;&#x27;&#x27;&gt;&lt;input&#x20;id&#x3d;&#x27;formInjection&#x27;&gt;&lt;&#x2f;form&gt;"));
    }

    @Test
    public void shouldEscapeDoubleQuote() {
        final String output = XssSanitizerUtil.stripXSS("\"asd");
        assertThat(output, is("&quot;asd"));
    }
}
