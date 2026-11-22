/* ==========================================================================
   Session Sniffer Live Theme Studio Controller (themes.html)
   - Renders 6 miniature built-in theme cards synced from models/themes.py
   - Powers live 20-token color editor, validation, preview & themes.json export/import
   ========================================================================== */

(function initSessionSnifferStudio() {
    'use strict';

    var Core = window.SSCore;
    if (!Core) {
        return;
    }

    var DATA = Core.DATA;
    var BUILTIN_BY_SLUG = Core.BUILTIN_BY_SLUG;
    var BUILTIN_NAME_SET = Core.BUILTIN_NAME_SET;
    var HEX_COLOR_RE = Core.HEX_COLOR_RE;
    var tSite = Core.tSite;
    var tApp = Core.tApp;
    var showToast = Core.showToast;
    var themeState = Core.getThemeState();

    var activeCategory = DATA.themeCategories[0];
    var baseSelectWired = false;

    function buildBuiltinThemeCards() {
        var grid = document.getElementById('builtin-theme-cards');
        var baseSelect = document.getElementById('studio-base-select');
        if (!grid) {
            return;
        }
        grid.innerHTML = '';
        if (baseSelect) {
            baseSelect.innerHTML = '';
        }

        DATA.builtinThemes.forEach(function addThemeCard(theme) {
            var c = theme.colors;
            var displayThemeName = tApp(theme.name);

            if (baseSelect) {
                var option = document.createElement('option');
                option.value = theme.slug;
                option.textContent = displayThemeName;
                baseSelect.appendChild(option);
            }

            var card = document.createElement('button');
            card.type = 'button';
            card.className = 'theme-preset-card';
            card.setAttribute('data-theme-slug', theme.slug);
            card.setAttribute('role', 'listitem');

            var scene = document.createElement('div');
            scene.className = 'theme-card-scene';
            scene.style.background = c.background;

            var miniBar = document.createElement('div');
            miniBar.className = 'theme-card-mini-bar';
            miniBar.style.background = c.menubar;
            miniBar.style.borderColor = c.border;

            [c.danger, c.warning, c.success].forEach(function addDot(col) {
                var d = document.createElement('span');
                d.className = 'theme-card-mini-dot';
                d.style.background = col;
                miniBar.appendChild(d);
            });

            var miniTable = document.createElement('div');
            miniTable.className = 'theme-card-mini-table';
            miniTable.style.borderColor = c.border;
            miniTable.style.background = c.table;

            var thead = document.createElement('div');
            thead.className = 'theme-card-mini-thead';
            thead.style.background = c.table_header;
            thead.style.borderBottomColor = c.accent;
            miniTable.appendChild(thead);

            var rowConfigs = [
                { bg: c.table, text: c.text_strong, pill: c.success },
                { bg: c.table_alt, text: c.text, pill: c.warning },
                { bg: c.selection, text: c.text_strong, pill: c.accent },
            ];
            rowConfigs.forEach(function addRow(rc) {
                var row = document.createElement('div');
                row.className = 'theme-card-mini-row';
                row.style.background = rc.bg;

                var textBar = document.createElement('span');
                textBar.className = 'theme-card-mini-text';
                textBar.style.background = rc.text;
                textBar.style.opacity = '0.78';

                var pill = document.createElement('span');
                pill.className = 'theme-card-mini-pill';
                pill.style.background = rc.pill;

                row.appendChild(textBar);
                row.appendChild(pill);
                miniTable.appendChild(row);
            });

            scene.appendChild(miniBar);
            scene.appendChild(miniTable);

            var caption = document.createElement('div');
            caption.className = 'theme-card-caption';

            var nameEl = document.createElement('span');
            nameEl.className = 'theme-card-name';
            nameEl.textContent = displayThemeName;

            var swatches = document.createElement('span');
            swatches.className = 'theme-card-swatches';
            [c.background, c.surface, c.accent, c.success, c.danger].forEach(function addSwatch(hex) {
                var dot = document.createElement('span');
                dot.style.background = hex;
                swatches.appendChild(dot);
            });

            caption.appendChild(nameEl);
            caption.appendChild(swatches);

            card.appendChild(scene);
            card.appendChild(caption);

            card.addEventListener('click', function onClickPresetCard() {
                Core.setBuiltinTheme(theme.slug);
                showToast(tSite('studio.toast_applied', { name: tApp(theme.name) }));
            });

            grid.appendChild(card);
        });

        if (baseSelect) {
            baseSelect.value = themeState.baseSlug;
            if (!baseSelectWired) {
                baseSelectWired = true;
                baseSelect.addEventListener('change', function onBaseChange() {
                    Core.setBuiltinTheme(baseSelect.value);
                });
            }
        }

        Core.updateThemeSelectionIndicators();
    }

    function buildStudioCategoryTabs() {
        var container = document.getElementById('studio-category-tabs');
        if (!container) {
            return;
        }
        container.innerHTML = '';

        DATA.themeCategories.forEach(function addTab(category) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'studio-tab-btn' + (category === activeCategory ? ' is-active' : '');
            btn.setAttribute('role', 'tab');
            btn.setAttribute('aria-selected', category === activeCategory ? 'true' : 'false');
            btn.textContent = tApp(category);

            btn.addEventListener('click', function onSelectCat() {
                activeCategory = category;
                container.querySelectorAll('.studio-tab-btn').forEach(function toggle(other) {
                    var active = other === btn;
                    other.classList.toggle('is-active', active);
                    other.setAttribute('aria-selected', active ? 'true' : 'false');
                });
                renderStudioTokens();
            });

            container.appendChild(btn);
        });
    }

    function renderStudioTokens() {
        var grid = document.getElementById('studio-tokens-grid');
        if (!grid) {
            return;
        }
        grid.innerHTML = '';

        DATA.themeTokens
            .filter(function matchCategory(token) { return token.category === activeCategory; })
            .forEach(function renderToken(token) {
                var currentHex = themeState.colors[token.name] || '#121212';
                var labelText = tApp(token.label);

                var row = document.createElement('div');
                row.className = 'token-row';

                var top = document.createElement('div');
                top.className = 'token-row-top';

                var label = document.createElement('span');
                label.className = 'token-label';
                label.textContent = labelText;

                var key = document.createElement('span');
                key.className = 'token-key';
                key.setAttribute('dir', 'ltr');
                key.textContent = '@' + token.name;

                top.appendChild(label);
                top.appendChild(key);

                var desc = document.createElement('p');
                desc.className = 'token-desc';
                desc.textContent = tApp(token.description);

                var controls = document.createElement('div');
                controls.className = 'token-controls';

                var picker = document.createElement('input');
                picker.type = 'color';
                picker.className = 'token-color-picker';
                picker.value = currentHex;
                picker.setAttribute('aria-label', labelText);

                var hexInput = document.createElement('input');
                hexInput.type = 'text';
                hexInput.className = 'token-hex-input';
                hexInput.setAttribute('dir', 'ltr');
                hexInput.value = currentHex;
                hexInput.maxLength = 7;
                hexInput.spellcheck = false;
                hexInput.setAttribute('aria-label', labelText + ' hex');

                picker.addEventListener('input', function onPick() {
                    var value = picker.value.toLowerCase();
                    hexInput.value = value;
                    Core.applyCustomColorLive(token.name, value);
                });

                hexInput.addEventListener('input', function onTypeHex() {
                    var value = hexInput.value.trim().toLowerCase();
                    if (HEX_COLOR_RE.test(value)) {
                        picker.value = value;
                        Core.applyCustomColorLive(token.name, value);
                    }
                });

                hexInput.addEventListener('blur', function onBlurHex() {
                    var value = hexInput.value.trim().toLowerCase();
                    if (!HEX_COLOR_RE.test(value)) {
                        hexInput.value = themeState.colors[token.name];
                    }
                });

                controls.appendChild(picker);
                controls.appendChild(hexInput);

                row.appendChild(top);
                row.appendChild(desc);
                row.appendChild(controls);
                grid.appendChild(row);
            });
    }

    function validateCustomThemeName(rawName) {
        var trimmed = rawName.trim();
        if (!trimmed) {
            return tSite('studio.err_empty');
        }
        if (trimmed.length > DATA.themeNameMaxLength) {
            return tSite('studio.err_max_len', { max: DATA.themeNameMaxLength });
        }
        if (BUILTIN_NAME_SET[trimmed.toLowerCase()]) {
            return tSite('studio.err_reserved', { name: trimmed });
        }
        return '';
    }

    function buildThemesFilePayload() {
        var orderedColors = {};
        DATA.themeTokens.forEach(function copyOrdered(token) {
            orderedColors[token.name] = (themeState.colors[token.name] || '#121212').toLowerCase();
        });
        var safeName = themeState.customName.trim() || 'My Custom Theme';
        if (BUILTIN_NAME_SET[safeName.toLowerCase()]) {
            safeName = safeName + ' Custom';
        }
        return {
            custom_themes: [
                {
                    name: safeName.slice(0, DATA.themeNameMaxLength),
                    colors: orderedColors,
                },
            ],
        };
    }

    function updateStudioJsonOutput() {
        var pre = document.getElementById('studio-json-output');
        var validationEl = document.getElementById('studio-name-validation');
        var error = validateCustomThemeName(themeState.customName);

        if (validationEl) {
            validationEl.textContent = error;
        }
        if (pre) {
            pre.textContent = JSON.stringify(buildThemesFilePayload(), null, 4);
        }
    }

    function initThemeStudioActions() {
        var nameInput = document.getElementById('custom-theme-name');
        if (nameInput) {
            nameInput.maxLength = DATA.themeNameMaxLength;
            nameInput.value = themeState.customName;
            nameInput.addEventListener('input', function onNameInput() {
                Core.setCustomThemeName(nameInput.value);
                updateStudioJsonOutput();
            });
        }

        var downloadBtn = document.getElementById('studio-download-btn');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', function onDownloadJson() {
                var error = validateCustomThemeName(themeState.customName);
                if (error) {
                    showToast(error);
                    if (nameInput) {
                        nameInput.focus();
                    }
                    return;
                }
                var jsonText = JSON.stringify(buildThemesFilePayload(), null, 4) + '\r\n';
                var blob = new Blob([jsonText], { type: 'application/json;charset=utf-8' });
                var url = URL.createObjectURL(blob);
                var link = document.createElement('a');
                link.href = url;
                link.download = 'themes.json';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
                showToast(tSite('studio.toast_downloaded'));
            });
        }

        var copyBtn = document.getElementById('studio-copy-btn');
        var copyLabel = document.getElementById('studio-copy-label');
        if (copyBtn) {
            copyBtn.addEventListener('click', function onCopyJson() {
                var jsonText = JSON.stringify(buildThemesFilePayload(), null, 4);
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(jsonText).then(function copied() {
                        if (copyLabel) {
                            copyLabel.textContent = tSite('studio.btn_copied');
                            window.setTimeout(function restore() { copyLabel.textContent = tSite('studio.btn_copy'); }, 1800);
                        }
                        showToast(tSite('preview.toast_copied'));
                    }).catch(function fallback() {
                        showToast(tSite('studio.btn_download'));
                    });
                } else {
                    showToast(tSite('studio.btn_download'));
                }
            });
        }

        var importInput = document.getElementById('studio-import-input');
        if (importInput) {
            importInput.addEventListener('change', function onImportFile() {
                var file = importInput.files && importInput.files[0];
                if (!file) {
                    return;
                }
                var reader = new FileReader();
                reader.onload = function onFileRead() {
                    try {
                        var parsed = JSON.parse(String(reader.result || ''));
                        if (!parsed || !Array.isArray(parsed.custom_themes) || parsed.custom_themes.length === 0) {
                            showToast(tSite('studio.toast_invalid_json'));
                            return;
                        }
                        var first = parsed.custom_themes[0];
                        if (!first || typeof first.name !== 'string' || !first.colors || typeof first.colors !== 'object') {
                            showToast(tSite('studio.toast_invalid_json'));
                            return;
                        }
                        themeState.customName = first.name.slice(0, DATA.themeNameMaxLength);
                        if (nameInput) {
                            nameInput.value = themeState.customName;
                        }
                        DATA.themeTokens.forEach(function loadToken(token) {
                            var val = first.colors[token.name];
                            if (typeof val === 'string' && HEX_COLOR_RE.test(val.trim())) {
                                themeState.colors[token.name] = val.trim().toLowerCase();
                            }
                        });
                        renderStudioTokens();
                        Core.applyAllStudioColorsLive();
                        showToast(tSite('studio.toast_imported', { name: themeState.customName }));
                    } catch (_err) {
                        showToast(tSite('studio.toast_invalid_json'));
                    } finally {
                        importInput.value = '';
                    }
                };
                reader.readAsText(file);
            });
        }

        var resetBtn = document.getElementById('studio-reset-btn');
        if (resetBtn) {
            resetBtn.addEventListener('click', function onReset() {
                Core.setBuiltinTheme(themeState.baseSlug);
                showToast(tSite('studio.toast_applied', { name: tApp(BUILTIN_BY_SLUG[themeState.baseSlug].name) }));
            });
        }
    }

    Core.onThemeChange(function handleThemeChange(reason) {
        if (reason === 'builtin') {
            var baseSelect = document.getElementById('studio-base-select');
            if (baseSelect) {
                baseSelect.value = themeState.baseSlug;
            }
            renderStudioTokens();
        }
        updateStudioJsonOutput();
    });

    Core.onLanguageChange(function handleLanguageChange() {
        buildBuiltinThemeCards();
        buildStudioCategoryTabs();
        renderStudioTokens();
        updateStudioJsonOutput();
    });

    buildBuiltinThemeCards();
    buildStudioCategoryTabs();
    renderStudioTokens();
    updateStudioJsonOutput();
    initThemeStudioActions();
}());
