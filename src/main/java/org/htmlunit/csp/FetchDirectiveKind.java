/*
 * Copyright (c) 2023-2026 Ronald Brill.
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

/**
 * Enumerates the CSP fetch directive names and provides their fallback chains.
 * <p>
 * Each constant corresponds to a fetch directive defined in the
 * <a href="https://w3c.github.io/webappsec-csp/#directives-fetch">CSP specification</a>.
 * The {@linkplain #getFetchDirectiveFallbackList(FetchDirectiveKind) fallback list}
 * implements the
 * <a href="https://w3c.github.io/webappsec-csp/#directive-fallback-list">directive
 * fallback list</a> algorithm, determining which directive governs a request when the
 * most specific directive is not present.
 * </p>
 * <p>
 * For example, the fallback chain for {@link #ScriptSrcElem} is:
 * {@code script-src-elem} → {@code script-src} → {@code default-src}.
 * </p>
 */
public enum FetchDirectiveKind {
    /** The {@code child-src} fetch directive. */
    ChildSrc("child-src"),

    /** The {@code connect-src} fetch directive. */
    ConnectSrc("connect-src"),

    /** The {@code default-src} fetch directive (fallback for all other fetch directives). */
    DefaultSrc("default-src"),

    /** The {@code font-src} fetch directive. */
    FontSrc("font-src"),

    /** The {@code frame-src} fetch directive. */
    FrameSrc("frame-src"),

    /** The {@code img-src} fetch directive. */
    ImgSrc("img-src"),

    /** The {@code manifest-src} fetch directive. */
    ManifestSrc("manifest-src"),

    /** The {@code media-src} fetch directive. */
    MediaSrc("media-src"),

    /** The {@code object-src} fetch directive. */
    ObjectSrc("object-src"),

    /** The (deprecated) {@code prefetch-src} fetch directive. */
    PrefetchSrc("prefetch-src"),

    /** The {@code script-src-attr} fetch directive. */
    ScriptSrcAttr("script-src-attr"),

    /** The {@code script-src} fetch directive. */
    ScriptSrc("script-src"),

    /** The {@code script-src-elem} fetch directive. */
    ScriptSrcElem("script-src-elem"),

    /** The {@code style-src-attr} fetch directive. */
    StyleSrcAttr("style-src-attr"),

    /** The {@code style-src} fetch directive. */
    StyleSrc("style-src"),

    /** The {@code style-src-elem} fetch directive. */
    StyleSrcElem("style-src-elem"),

    /** The {@code worker-src} fetch directive. */
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

    /**
     * Returns the lowercase directive name as it appears in a serialized CSP
     * (e.g. {@code "script-src-elem"}, {@code "default-src"}).
     *
     * @return the directive name string
     */
    public String getRepr() {
        return repr_;
    }

    /**
     * Looks up a {@link FetchDirectiveKind} by its lowercase directive name.
     *
     * @param name the directive name to look up (e.g. {@code "script-src"})
     * @return the matching {@link FetchDirectiveKind}, or {@code null} if the
     *         name does not correspond to a known fetch directive
     */
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
