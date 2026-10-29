/* =========================================================
   CYBERSHIELD
   Frontend Utilities
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {

    /*
     * Automatically hide temporary SOC flash messages while keeping persistent portal alerts visible.
     */
    const alerts = document.querySelectorAll(
        ".flash-message"
    );

    alerts.forEach((alert) => {

        setTimeout(() => {

            alert.style.transition = "opacity 0.3s ease";
            alert.style.opacity = "0";

            setTimeout(() => {
                alert.remove();
            }, 300);

        }, 6000);

    });


    /*
     * Confirm potentially destructive SOC actions.
     */
    const dangerActions = document.querySelectorAll(
        "[data-confirm]"
    );

    dangerActions.forEach((element) => {

        element.addEventListener("click", (event) => {

            const message =
                element.getAttribute("data-confirm");

            if (message && !window.confirm(message)) {
                event.preventDefault();
            }

        });

    });


    /*
     * Prevent accidental double submission of forms.
     */
    const forms = document.querySelectorAll("form");

    forms.forEach((form) => {

        form.addEventListener("submit", () => {

            const submitButtons = form.querySelectorAll(
                'button[type="submit"]'
            );

            submitButtons.forEach((button) => {

                if (!button.dataset.allowMultiple) {

                    button.dataset.originalText =
                        button.textContent;

                    button.textContent = "PROCESSING...";

                    button.disabled = true;

                }

            });

        });

    });


    /*
     * Allow analyst tables to highlight the selected row.
     */
    const tableRows = document.querySelectorAll(
        ".data-table tbody tr"
    );

    tableRows.forEach((row) => {

        row.addEventListener("click", () => {

            tableRows.forEach((item) => {
                item.classList.remove("selected-row");
            });

            row.classList.add("selected-row");

        });

    });


    /*
     * Add a simple live timestamp where requested.
     */
    const liveClocks = document.querySelectorAll(
        "[data-live-clock]"
    );

    const updateClocks = () => {

        const now = new Date();

        liveClocks.forEach((clock) => {

            clock.textContent =
                now.toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit"
                });

        });

    };

    if (liveClocks.length > 0) {

        updateClocks();

        setInterval(updateClocks, 1000);

    }


    /*
     * Console branding.
     */
    console.log(
        "%cCyberShield SOC",
        "color:#39ff88;font-weight:bold;font-size:16px;"
    );

    console.log(
        "Cyber Defense Learning & SOC Platform"
    );

});