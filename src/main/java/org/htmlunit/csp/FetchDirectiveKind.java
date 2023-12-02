/*
 * Copyright (c) 2023 Ronald Brill.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.htmlunit.csp;

public enum FetchDirectiveKind {
    /** ChildSrc("child-src"). */
    ChildSrc("child-src"),

    /** ConnectSrc("connect-src"). */
    ConnectSrc("connect-src"),

    /** DefaultSrc("default-src"). */
    DefaultSrc("default-src"),

    /** FontSrc("font-src"). */
    FontSrc("font-src"),

    /** FrameSrc("frame-src"). */
    FrameSrc("frame-src"),

    /** ImgSrc("img-src"). */
    ImgSrc("img-src"),

    /** ManifestSrc("manifest-src"). */
    ManifestSrc("manifest-src"),

    /** MediaSrc("media-src"). */
    MediaSrc("media-src"),

    /** ObjectSrc("object-src"). */
    ObjectSrc("object-src"),

    /** PrefetchSrc("prefetch-src"). */
    PrefetchSrc("prefetch-src"),

    /** ScriptSrcAttr("script-src-attr"). */
    ScriptSrcAttr("script-src-attr"),

    /** ScriptSrc("script-src"). */
    ScriptSrc("script-src"),

    /** ScriptSrcElem("script-src-elem"). */
    ScriptSrcElem("script-src-elem"),

    /** StyleSrcAttr("style-src-attr"). */
    StyleSrcAttr("style-src-attr"),

    /** StyleSrc("style-src"). */
    StyleSrc("style-src"),

    /** StyleSrcElem("style-src-elem"). */
    StyleSrcElem("style-src-elem"),

    /** WorkerSrc("worker-src"). */
    WorkerSrc("worker-src");

    private final String repr_;

    FetchDirectiveKind(final String repr) {
        repr_ = repr;
    }

    public String getRepr() {
        return repr_;
    }

    // returns null if not matched
    public static FetchDirectiveKind fromString(final String name) {
        switch (name) {
            case "child-src":
                return ChildSrc;
            case "connect-src":
                return ConnectSrc;
            case "default-src":
                return DefaultSrc;
            case "font-src":
                return FontSrc;
            case "frame-src":
                return FrameSrc;
            case "img-src":
                return ImgSrc;
            case "manifest-src":
                return ManifestSrc;
            case "media-src":
                return MediaSrc;
            case "object-src":
                return ObjectSrc;
            case "prefetch-src":
                return PrefetchSrc;
            case "script-src-attr":
                return ScriptSrcAttr;
            case "script-src":
                return ScriptSrc;
            case "script-src-elem":
                return ScriptSrcElem;
            case "style-src-attr":
                return StyleSrcAttr;
            case "style-src":
                return StyleSrc;
            case "style-src-elem":
                return StyleSrcElem;
            case "worker-src":
                return WorkerSrc;
            default:
                return null;
        }
    }

    // https://w3c.github.io/webappsec-csp/#directive-fallback-list
    // Note the oddity that worker-src falls back to child-src then script-src
    // then directive-src, but frame-src falls back to child-src then directly default-src
    // Also note that `script-src` falls back to `default-src` for "unsafe-eval", but this
    // is done manually in prose rather than in this table
    // (in https://w3c.github.io/webappsec-csp/#can-compile-strings )
    // It is included here only for completeness
    private static final FetchDirectiveKind[] ScriptSrcFallback
                            = new FetchDirectiveKind[] {ScriptSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ScriptSrcElemFallback
                            = new FetchDirectiveKind[] {ScriptSrcElem, ScriptSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ScriptSrcAttrFallback
                            = new FetchDirectiveKind[] {ScriptSrcAttr, ScriptSrc, DefaultSrc};
    private static final FetchDirectiveKind[] StyleSrcFallback
                            = new FetchDirectiveKind[] {StyleSrc, DefaultSrc};
    private static final FetchDirectiveKind[] StyleSrcElemFallback
                            = new FetchDirectiveKind[] {StyleSrcElem, StyleSrc, DefaultSrc};
    private static final FetchDirectiveKind[] StyleSrcAttrFallback
                            = new FetchDirectiveKind[] {StyleSrcAttr, StyleSrc, DefaultSrc};
    private static final FetchDirectiveKind[] WorkerSrcFallback
                            = new FetchDirectiveKind[] {WorkerSrc, ChildSrc, ScriptSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ConnectSrcFallback
                            = new FetchDirectiveKind[] {ConnectSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ManifestSrcFallback
                            = new FetchDirectiveKind[] {ManifestSrc, DefaultSrc};
    private static final FetchDirectiveKind[] PrefetchSrcFallback
                            = new FetchDirectiveKind[] {PrefetchSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ObjectSrcFallback
                            = new FetchDirectiveKind[] {ObjectSrc, DefaultSrc};
    private static final FetchDirectiveKind[] FrameSrcFallback
                            = new FetchDirectiveKind[] {FrameSrc, ChildSrc, DefaultSrc };
    private static final FetchDirectiveKind[] MediaSrcFallback
                            = new FetchDirectiveKind[] {MediaSrc, DefaultSrc };
    private static final FetchDirectiveKind[] FontSrcFallback
                            = new FetchDirectiveKind[] {FontSrc, DefaultSrc };
    private static final FetchDirectiveKind[] ImgSrcFallback
                            = new FetchDirectiveKind[] {ImgSrc, DefaultSrc };

    static FetchDirectiveKind[] getFetchDirectiveFallbackList(final FetchDirectiveKind directive) {
        switch (directive) {
            case ScriptSrc:
                return ScriptSrcFallback;
            case ScriptSrcElem:
                return ScriptSrcElemFallback;
            case ScriptSrcAttr:
                return ScriptSrcAttrFallback;
            case StyleSrc:
                return StyleSrcFallback;
            case StyleSrcElem:
                return StyleSrcElemFallback;
            case StyleSrcAttr:
                return StyleSrcAttrFallback;
            case WorkerSrc:
                return WorkerSrcFallback;
            case ConnectSrc:
                return ConnectSrcFallback;
            case ManifestSrc:
                return ManifestSrcFallback;
            case PrefetchSrc:
                return PrefetchSrcFallback;
            case ObjectSrc:
                return ObjectSrcFallback;
            case FrameSrc:
                return FrameSrcFallback;
            case MediaSrc:
                return MediaSrcFallback;
            case FontSrc:
                return FontSrcFallback;
            case ImgSrc:
                return ImgSrcFallback;
            default:
                throw new IllegalArgumentException("Unknown fetch directive " + directive);
        }
    }
}
