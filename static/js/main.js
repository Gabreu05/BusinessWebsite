document.addEventListener('DOMContentLoaded', () => {
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('[data-nav]');

    if (!hamburger || !navMenu) {
        return;
    }

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
});
