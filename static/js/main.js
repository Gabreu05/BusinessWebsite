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

    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('[data-nav]');

    if (hamburger && navMenu) {
        const toggleMenu = () => {
            const isOpen = navMenu.classList.toggle('open');
            hamburger.setAttribute('aria-expanded', String(isOpen));
        };

        hamburger.addEventListener('click', toggleMenu);
        hamburger.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggleMenu();
            }
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
