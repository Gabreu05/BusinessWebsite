document.addEventListener('DOMContentLoaded', () => {
    const initializePasswordToggles = () => {
        document.querySelectorAll('.password-toggle').forEach((button) => {
            if (button.dataset.bound === 'true') {
                return;
            }
            button.dataset.bound = 'true';
            button.addEventListener('click', () => {
                const inputId = button.getAttribute('data-toggle');
                const input = document.getElementById(inputId);
                if (!input) {
                    return;
                }
                const reveal = input.type === 'password';
                input.type = reveal ? 'text' : 'password';
                button.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
                button.classList.toggle('revealed', reveal);
                button.textContent = reveal ? 'Hide' : 'Show';
                input.focus({ preventScroll: true });
                input.setSelectionRange(input.value.length, input.value.length);
            });
        });
    };

    initializePasswordToggles();

    const accountToggle = document.querySelector('[data-account-toggle]');
    const accountMenu = document.querySelector('[data-account-menu]');
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('[data-nav]');

    if (hamburger && navMenu) {
        const toggleMenu = () => {
            const isOpen = navMenu.classList.toggle('open');
            hamburger.setAttribute('aria-expanded', String(isOpen));
            if (accountMenu && accountMenu.classList.contains('open')) {
                accountMenu.classList.remove('open');
                accountToggle?.setAttribute('aria-expanded', 'false');
            }
        };

        hamburger.addEventListener('click', toggleMenu);
        hamburger.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggleMenu();
            }
        });
    }

    if (accountToggle && accountMenu) {
        const closeAccountMenu = () => {
            if (!accountMenu.classList.contains('open')) {
                return;
            }
            accountMenu.classList.remove('open');
            accountToggle.setAttribute('aria-expanded', 'false');
        };

        accountToggle.addEventListener('click', (event) => {
            event.stopPropagation();
            const willOpen = !accountMenu.classList.contains('open');
            if (willOpen && navMenu && navMenu.classList.contains('open')) {
                navMenu.classList.remove('open');
                hamburger?.setAttribute('aria-expanded', 'false');
            }
            const isOpen = accountMenu.classList.toggle('open');
            accountToggle.setAttribute('aria-expanded', String(isOpen));
        });

        accountMenu.addEventListener('click', (event) => {
            event.stopPropagation();
        });

        document.addEventListener('click', (event) => {
            const target = event.target;
            if (!(target instanceof Node)) {
                return;
            }
            if (accountMenu.contains(target) || accountToggle.contains(target)) {
                return;
            }
            closeAccountMenu();
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') {
                closeAccountMenu();
            }
        });
    }

    const quotePanel = document.querySelector('[data-quote-panel]');
    const quoteContent = document.querySelector('[data-quote-content]');
    const quoteTitleArea = document.querySelector('[data-quote-title]');
    const quoteClose = document.querySelector('[data-quote-close]');
    const quoteTemplates = document.querySelectorAll('[data-quote-template]');
    const quoteTriggers = Array.from(document.querySelectorAll('[data-quote-trigger]'));
    const quoteTemplateMap = new Map();
    const newConvoPanel = document.querySelector('[data-new-convo-panel]');
    const newConvoOpen = document.querySelector('[data-new-convo-open]');
    const newConvoClose = document.querySelector('[data-new-convo-close]');
    const newConvoSubject = document.getElementById('new-topic');
    const isInlineQuotePanel = quotePanel?.dataset.inlinePanel === 'true';
    let defaultQuoteMarkup = '';

    if (quoteContent) {
        defaultQuoteMarkup = quoteContent.innerHTML;
    }

    quoteTemplates.forEach((template) => {
        const id = template.getAttribute('data-quote-template');
        if (id) {
            quoteTemplateMap.set(id, template);
        }
    });

    const markQuoteAsRead = (quoteId, trigger) => {
        if (!trigger) {
            return;
        }
        const readUrl = trigger.dataset.quoteReadUrl;
        if (!readUrl || trigger.dataset.reading === 'true') {
            return;
        }

        trigger.dataset.reading = 'true';
        fetch(readUrl, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
            },
        })
            .then(() => {
                trigger.classList.remove('has-unread');
                trigger.dataset.quoteUnread = '0';
                const badge = trigger.querySelector('[data-quote-badge]');
                if (badge) {
                    badge.remove();
                }
                if (quoteContent && quoteContent.dataset.activeQuote === String(quoteId)) {
                    quoteContent
                        .querySelectorAll('.quote-message-row.is-unread')
                        .forEach((row) => row.classList.remove('is-unread'));
                }
            })
            .catch(() => {})
            .finally(() => {
                delete trigger.dataset.reading;
            });
    };

    const closeQuotePanel = () => {
        if (!quotePanel) {
            return;
        }
        quotePanel.classList.remove('open');
        if (!isInlineQuotePanel) {
            quotePanel.setAttribute('hidden', '');
            document.body.classList.remove('quote-panel-open');
        }
        if (quoteContent) {
            quoteContent.innerHTML = defaultQuoteMarkup;
            delete quoteContent.dataset.activeQuote;
        }
        if (quoteTitleArea) {
            quoteTitleArea.innerHTML = '';
        }
    };

    const openQuotePanel = (quoteId, trigger) => {
        if (!quotePanel || !quoteContent || !quoteTitleArea) {
            return;
        }
        const templateElement = quoteTemplateMap.get(quoteId);
        if (!templateElement) {
            return;
        }

        const fragment = templateElement.content
            ? templateElement.content.cloneNode(true)
            : templateElement.cloneNode(true);
        quoteContent.innerHTML = '';
        quoteContent.appendChild(fragment);
        quoteContent.scrollTo({ top: 0 });

        const headerParts = [];
        const topic = trigger?.dataset.quoteTopic || '';
        if (topic) {
            headerParts.push(`<h3>${topic}</h3>`);
        } else {
            headerParts.push(`<h3>Quote #${quoteId}</h3>`);
        }
        const submitted = trigger?.dataset.quoteSubmitted || '';
        const updated = trigger?.dataset.quoteUpdated;

        if (updated) {
            headerParts.push(`<p class="quote-conversation-header-meta">Last updated ${updated}</p>`);
        }
        if (submitted) {
            headerParts.push(`<p class="quote-conversation-header-meta">Created ${submitted}</p>`);
        }

        quoteTitleArea.innerHTML = headerParts.join('');
        quotePanel.classList.add('open');
        if (!isInlineQuotePanel) {
            quotePanel.removeAttribute('hidden');
            document.body.classList.add('quote-panel-open');
        }
        quoteContent.dataset.activeQuote = String(quoteId);

        if (trigger) {
            markQuoteAsRead(quoteId, trigger);
        }

        if (!isInlineQuotePanel && quoteClose) {
            quoteClose.focus({ preventScroll: true });
        }
    };

    if (quoteTriggers.length && quotePanel) {
        quoteTriggers.forEach((triggerElement) => {
            triggerElement.addEventListener('click', () => {
                const quoteId = triggerElement.dataset.quoteTrigger;
                if (quoteId) {
                    openQuotePanel(quoteId, triggerElement);
                }
            });
        });

        if (quoteClose) {
            quoteClose.addEventListener('click', () => {
                closeQuotePanel();
            });
        }

        if (!isInlineQuotePanel) {
            quotePanel.addEventListener('click', (event) => {
                if (event.target === quotePanel) {
                    closeQuotePanel();
                }
            });
        }

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && quotePanel.classList.contains('open')) {
                closeQuotePanel();
            }
        });
    }

    const handleNewConvoEsc = (event) => {
        if (event.key === 'Escape' && newConvoPanel?.classList.contains('open')) {
            closeNewConvo();
        }
    };

    const openNewConvo = () => {
        if (!newConvoPanel) {
            return;
        }
        newConvoPanel.removeAttribute('hidden');
        newConvoPanel.classList.add('open');
        newConvoSubject?.focus({ preventScroll: true });
        document.addEventListener('keydown', handleNewConvoEsc);
    };

    const closeNewConvo = () => {
        if (!newConvoPanel) {
            return;
        }
        newConvoPanel.classList.remove('open');
        newConvoPanel.setAttribute('hidden', '');
        document.removeEventListener('keydown', handleNewConvoEsc);
    };

    newConvoOpen?.addEventListener('click', openNewConvo);
    newConvoClose?.addEventListener('click', closeNewConvo);
    newConvoPanel?.addEventListener('click', (event) => {
        if (event.target === newConvoPanel) {
            closeNewConvo();
        }
    });

    const adminMenuToggles = document.querySelectorAll('[data-admin-menu-toggle]');
    if (adminMenuToggles.length) {
        const findMenu = (id) => {
            if (!id) {
                return null;
            }
            return document.querySelector(`[data-admin-menu="${id}"]`);
        };

        const closeAllMenus = (exceptId) => {
            adminMenuToggles.forEach((toggle) => {
                const targetId = toggle.dataset.adminMenuToggle;
                if (!targetId || targetId === exceptId) {
                    return;
                }
                const menu = findMenu(targetId);
                if (!menu || menu.hasAttribute('hidden')) {
                    return;
                }
                menu.classList.remove('open');
                menu.setAttribute('hidden', '');
                toggle.setAttribute('aria-expanded', 'false');
            });
        };

        adminMenuToggles.forEach((toggle) => {
            const targetId = toggle.dataset.adminMenuToggle;
            const menu = findMenu(targetId);
            if (!targetId || !menu) {
                return;
            }

            const closeButtons = menu.querySelectorAll('[data-admin-menu-close]');

            const setState = (open) => {
                if (open) {
                    closeAllMenus(targetId);
                    menu.classList.add('open');
                    menu.removeAttribute('hidden');
                    toggle.setAttribute('aria-expanded', 'true');
                    menu.scrollIntoView({ behavior: 'smooth', block: 'start' });
                } else {
                    menu.classList.remove('open');
                    menu.setAttribute('hidden', '');
                    toggle.setAttribute('aria-expanded', 'false');
                }
            };

            toggle.addEventListener('click', () => {
                setState(menu.hasAttribute('hidden'));
            });

            closeButtons.forEach((button) => {
                button.addEventListener('click', () => setState(false));
            });

            menu.addEventListener('keydown', (event) => {
                if (event.key === 'Escape') {
                    setState(false);
                }
            });
        });

        document.addEventListener('click', (event) => {
            const target = event.target;
            if (!(target instanceof Node)) {
                return;
            }
            adminMenuToggles.forEach((toggle) => {
                const targetId = toggle.dataset.adminMenuToggle;
                const menu = findMenu(targetId);
                if (!menu || menu.hasAttribute('hidden')) {
                    return;
                }
                if (!menu.contains(target) && !toggle.contains(target)) {
                    menu.classList.remove('open');
                    menu.setAttribute('hidden', '');
                    toggle.setAttribute('aria-expanded', 'false');
                }
            });
        });
    }

    const flashMessages = document.querySelectorAll('.flash');
    if (flashMessages.length) {
        setTimeout(() => {
            flashMessages.forEach((message) => {
                message.classList.add('flash-hide');
                setTimeout(() => message.remove(), 300);
            });
        }, 15000);
    }
});
