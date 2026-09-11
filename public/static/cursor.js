/**
 * SecurePass Auditor - Minimal Circular Dot Cursor (◉)
 * Replaces default mouse cursor with a smooth, lightweight glowing circular dot.
 * Center is bright and visible; subtle glow; slightly grows on interactive hover; shrinks on click.
 * Completely disabled on touch/mobile devices and respects prefers-reduced-motion.
 */
(function() {
    'use strict';

    // Disable completely on touch/mobile devices or when hover is not supported
    if (window.matchMedia('(pointer: coarse)').matches || !window.matchMedia('(hover: hover)').matches) {
        return;
    }

    function initCursor() {
        if (document.getElementById('customCursor')) return;

        const cursor = document.createElement('div');
        cursor.id = 'customCursor';
        cursor.className = 'custom-cursor';
        cursor.setAttribute('aria-hidden', 'true');

        const dot = document.createElement('div');
        dot.className = 'custom-cursor-dot';
        cursor.appendChild(dot);

        document.body.appendChild(cursor);

        let isVisible = false;

        // Smooth position tracking at hardware GPU refresh rate
        window.addEventListener('pointermove', function(e) {
            cursor.style.transform = 'translate3d(' + e.clientX + 'px, ' + e.clientY + 'px, 0)';
            if (!isVisible) {
                cursor.classList.add('visible');
                isVisible = true;
            }
        }, { passive: true });

        // Interactive hover detection (buttons, links, inputs, selects, swatches, clickable elements)
        const interactiveSelector = 'a, button, input, select, textarea, label, [role="button"], [tabindex]:not([tabindex="-1"]), .btn, .nav-link, .accent-swatch, summary, .clickable';

        document.addEventListener('pointerover', function(e) {
            if (e.target && e.target.closest && e.target.closest(interactiveSelector)) {
                cursor.classList.add('hovering');
            }
        }, { passive: true });

        document.addEventListener('pointerout', function(e) {
            if (e.target && e.target.closest && e.target.closest(interactiveSelector)) {
                cursor.classList.remove('hovering');
            }
        }, { passive: true });

        // Click interaction: briefly shrink and return to normal size
        window.addEventListener('pointerdown', function() {
            cursor.classList.add('clicking');
        }, { passive: true });

        window.addEventListener('pointerup', function() {
            cursor.classList.remove('clicking');
        }, { passive: true });

        // Hide when mouse leaves window, show when entering
        document.addEventListener('mouseleave', function() {
            cursor.classList.remove('visible');
            isVisible = false;
        });

        document.addEventListener('mouseenter', function() {
            cursor.classList.add('visible');
            isVisible = true;
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initCursor);
    } else {
        initCursor();
    }
})();
