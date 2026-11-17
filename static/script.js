/* Dream Villa - small enhancements (no libraries needed) */
(function () {
    "use strict";

    var navbar = document.querySelector(".navbar");
    var navLinks = document.querySelectorAll("nav a[href^='#'], nav a[href='/']");

    /* ---------- Back-to-top button ---------- */
    var toTop = document.createElement("button");
    toTop.className = "back-to-top";
    toTop.setAttribute("aria-label", "Back to top");
    toTop.innerHTML = "&uarr;";
    toTop.addEventListener("click", function () {
        window.scrollTo({ top: 0, behavior: "smooth" });
    });
    document.body.appendChild(toTop);

    /* ---------- Navbar shrink + back-to-top visibility ---------- */
    function onScroll() {
        var y = window.scrollY || window.pageYOffset;
        if (navbar) navbar.classList.toggle("scrolled", y > 40);
        toTop.classList.toggle("show", y > 700);
    }
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();

    /* ---------- Highlight the nav link of the section in view ---------- */
    function navTargetFor(id) {
        if (id === "rooms" || /^room\d-details$/.test(id)) return "#rooms";
        if (id === "amenities" || /-details$/.test(id)) return "#amenities";
        if (id === "resort-tour") return "#resort-tour";
        if (id === "contact") return "#contact";
        return "/";
    }

    function setActive(href) {
        navLinks.forEach(function (a) {
            a.classList.toggle("active", a.getAttribute("href") === href);
        });
    }

    if ("IntersectionObserver" in window) {
        var spy = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) setActive(navTargetFor(entry.target.id));
            });
        }, { rootMargin: "-45% 0px -50% 0px" });

        document.querySelectorAll("main.hero, section[id]").forEach(function (el) {
            if (!el.id) el.id = "top";
            spy.observe(el);
        });
    }

    /* ---------- Scroll reveal ---------- */
    var revealSelector = [
        ".intro > *",
        ".section-heading",
        ".detail-heading",
        ".room-card",
        ".amenity-card",
        ".contact-card",
        ".room-video-container",
        ".tour-video-container",
        ".photo-gallery img",
        ".booking-banner",
        ".detail-book-btn",
        ".back-link"
    ].join(",");

    var reduceMotion = window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if ("IntersectionObserver" in window && !reduceMotion) {
        var reveal = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                var el = entry.target;
                el.classList.add("is-visible");
                reveal.unobserve(el);

                // Remove helper classes afterwards so hover effects work normally
                var delay = parseFloat(el.style.transitionDelay) || 0;
                setTimeout(function () {
                    el.classList.remove("js-reveal", "is-visible");
                    el.style.transitionDelay = "";
                }, 1000 + delay);
            });
        }, { threshold: 0.12, rootMargin: "0px 0px -40px 0px" });

        document.querySelectorAll(revealSelector).forEach(function (el) {
            var siblings = el.parentElement ? Array.prototype.indexOf.call(el.parentElement.children, el) : 0;
            el.style.transitionDelay = ((siblings % 4) * 90) + "ms";
            el.classList.add("js-reveal");
            reveal.observe(el);
        });
    }

    /* ---------- Photo lightbox ---------- */
    var box = document.createElement("div");
    box.className = "lightbox";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.innerHTML = '<button class="lightbox-close" aria-label="Close photo">&times;</button><img alt="">';
    document.body.appendChild(box);

    var boxImg = box.querySelector("img");

    function openBox(src, alt) {
        boxImg.src = src;
        boxImg.alt = alt || "";
        box.classList.add("open");
        document.body.style.overflow = "hidden";
    }

    function closeBox() {
        box.classList.remove("open");
        document.body.style.overflow = "";
    }

    document.querySelectorAll(".photo-gallery img").forEach(function (img) {
        img.addEventListener("click", function () {
            openBox(img.currentSrc || img.src, img.alt);
        });
    });

    box.addEventListener("click", function (e) {
        if (e.target !== boxImg) closeBox();
    });

    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") closeBox();
    });
})();
function showAdminPage(pageId, button) {
    // Hide all management pages
    document.querySelectorAll('.admin-page').forEach(function(page) {
        page.classList.remove('active');
    });

    // Hide all overview elements
    document.querySelectorAll('.admin-overview').forEach(function(item) {
        item.style.display = 'none';
    });

    // Show selected page
    if (pageId === 'overview') {
        document.querySelectorAll('.admin-overview').forEach(function(item) {
            item.style.display = '';
        });
    } else {
        const selectedPage = document.getElementById(pageId);

        if (selectedPage) {
            selectedPage.classList.add('active');
        }
    }

    // Update active sidebar button
    document.querySelectorAll('.sidebar-link').forEach(function(link) {
        link.classList.remove('active');
    });

    button.classList.add('active');
}
