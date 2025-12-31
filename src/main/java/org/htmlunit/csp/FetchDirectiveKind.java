/*
 * Copyright (c) 2023-2025 Ronald Brill.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0
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

    // https://w3c.github.io/webappsec-csp/#directive-fallback-list
    // Note the oddity that worker-src falls back to child-src then script-src
    // then directive-src, but frame-src falls back to child-src then directly default-src
    // Also note that `script-src` falls back to `default-src` for "unsafe-eval", but this
    // is done manually in prose rather than in this table
    // (in https://w3c.github.io/webappsec-csp/#can-compile-strings )
    // It is included here only for completeness
    private static final FetchDirectiveKind[] ScriptSrcFallback = {ScriptSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ScriptSrcElemFallback = {ScriptSrcElem, ScriptSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ScriptSrcAttrFallback = {ScriptSrcAttr, ScriptSrc, DefaultSrc};
    private static final FetchDirectiveKind[] StyleSrcFallback = {StyleSrc, DefaultSrc};
    private static final FetchDirectiveKind[] StyleSrcElemFallback = {StyleSrcElem, StyleSrc, DefaultSrc};
    private static final FetchDirectiveKind[] StyleSrcAttrFallback = {StyleSrcAttr, StyleSrc, DefaultSrc};
    private static final FetchDirectiveKind[] WorkerSrcFallback = {WorkerSrc, ChildSrc, ScriptSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ConnectSrcFallback = {ConnectSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ManifestSrcFallback = {ManifestSrc, DefaultSrc};
    private static final FetchDirectiveKind[] PrefetchSrcFallback = {PrefetchSrc, DefaultSrc};
    private static final FetchDirectiveKind[] ObjectSrcFallback = {ObjectSrc, DefaultSrc};
    private static final FetchDirectiveKind[] FrameSrcFallback = {FrameSrc, ChildSrc, DefaultSrc };
    private static final FetchDirectiveKind[] MediaSrcFallback = {MediaSrc, DefaultSrc };
    private static final FetchDirectiveKind[] FontSrcFallback = {FontSrc, DefaultSrc };
    private static final FetchDirectiveKind[] ImgSrcFallback = {ImgSrc, DefaultSrc };

    private final String repr_;

    FetchDirectiveKind(final String repr) {
        repr_ = repr;
    }

    public String getRepr() {
        return repr_;
    }

    // returns null if not matched
    public static FetchDirectiveKind fromString(final String name) {
        return switch (name) {
            case "child-src" -> ChildSrc;
            case "connect-src" -> ConnectSrc;
            case "default-src" -> DefaultSrc;
            case "font-src" -> FontSrc;
            case "frame-src" -> FrameSrc;
            case "img-src" -> ImgSrc;
            case "manifest-src" -> ManifestSrc;
            case "media-src" -> MediaSrc;
            case "object-src" -> ObjectSrc;
            case "prefetch-src" -> PrefetchSrc;
            case "script-src-attr" -> ScriptSrcAttr;
            case "script-src" -> ScriptSrc;
            case "script-src-elem" -> ScriptSrcElem;
            case "style-src-attr" -> StyleSrcAttr;
            case "style-src" -> StyleSrc;
            case "style-src-elem" -> StyleSrcElem;
            case "worker-src" -> WorkerSrc;
            default -> null;
        };
    }

    static FetchDirectiveKind[] getFetchDirectiveFallbackList(final FetchDirectiveKind directive) {
        return switch (directive) {
            case ScriptSrc -> ScriptSrcFallback;
            case ScriptSrcElem -> ScriptSrcElemFallback;
            case ScriptSrcAttr -> ScriptSrcAttrFallback;
            case StyleSrc -> StyleSrcFallback;
            case StyleSrcElem -> StyleSrcElemFallback;
            case StyleSrcAttr -> StyleSrcAttrFallback;
            case WorkerSrc -> WorkerSrcFallback;
            case ConnectSrc -> ConnectSrcFallback;
            case ManifestSrc -> ManifestSrcFallback;
            case PrefetchSrc -> PrefetchSrcFallback;
            case ObjectSrc -> ObjectSrcFallback;
            case FrameSrc -> FrameSrcFallback;
            case MediaSrc -> MediaSrcFallback;
            case FontSrc -> FontSrcFallback;
            case ImgSrc -> ImgSrcFallback;
            default -> throw new IllegalArgumentException("Unknown fetch directive " + directive);
        };
    }
}
