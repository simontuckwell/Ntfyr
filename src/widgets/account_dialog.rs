use adw::prelude::*;
use adw::subclass::prelude::*;
use gettextrs::gettext;
use glib::subclass::Signal;
use gtk::{gio, glib};
use ntfy_daemon::credentials::Credential;
use ntfy_daemon::models::{Account, AuthKind};
use once_cell::sync::Lazy;

const AUTH_MODE_BASIC: u32 = 0;
const AUTH_MODE_TOKEN: u32 = 1;

mod imp {
    use super::*;

    #[derive(gtk::CompositeTemplate, Default)]
    #[template(resource = "/io/github/tobagin/Ntfyr/ui/account_dialog.ui")]
    pub struct NtfyrAccountDialog {
        #[template_child]
        pub auth_mode_row: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub username_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub password_entry: TemplateChild<adw::PasswordEntryRow>,
        #[template_child]
        pub token_entry: TemplateChild<adw::PasswordEntryRow>,
        #[template_child]
        pub save_btn: TemplateChild<gtk::Button>,
        pub server_url: once_cell::sync::OnceCell<String>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for NtfyrAccountDialog {
        const NAME: &'static str = "NtfyrAccountDialog";
        type Type = super::NtfyrAccountDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.bind_template_callbacks();
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for NtfyrAccountDialog {
        fn signals() -> &'static [Signal] {
            static SIGNALS: Lazy<Vec<Signal>> = Lazy::new(|| vec![Signal::builder("save").build()]);
            SIGNALS.as_ref()
        }
    }

    impl WidgetImpl for NtfyrAccountDialog {}
    impl AdwDialogImpl for NtfyrAccountDialog {}

    #[gtk::template_callbacks]
    impl NtfyrAccountDialog {
        #[template_callback]
        fn on_save_clicked(&self) {
            self.obj().emit_by_name::<()>("save", &[]);
            self.obj().close();
        }
    }
}

glib::wrapper! {
    pub struct NtfyrAccountDialog(ObjectSubclass<imp::NtfyrAccountDialog>)
        @extends gtk::Widget, adw::Dialog,
        @implements gio::ActionMap, gio::ActionGroup, gtk::Root, gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::Native, gtk::ShortcutManager;
}

impl NtfyrAccountDialog {
    pub fn new(server_url: String) -> Self {
        let obj: Self = glib::Object::builder().build();
        obj.imp().server_url.set(server_url).unwrap();

        let this = obj.clone();
        obj.imp()
            .auth_mode_row
            .connect_selected_notify(move |_| this.update_auth_rows_visibility());
        obj.update_auth_rows_visibility();

        obj
    }

    fn update_auth_rows_visibility(&self) {
        let imp = self.imp();
        let token_mode = imp.auth_mode_row.selected() == AUTH_MODE_TOKEN;
        imp.username_entry.set_visible(!token_mode);
        imp.password_entry.set_visible(!token_mode);
        imp.token_entry.set_visible(token_mode);
    }

    pub fn set_account(&self, account: &Account) {
        let imp = self.imp();

        imp.auth_mode_row.set_selected(match account.auth_kind {
            AuthKind::Bearer => AUTH_MODE_TOKEN,
            AuthKind::Basic => AUTH_MODE_BASIC,
        });
        if let Some(username) = &account.username {
            imp.username_entry.set_text(username);
        }
        imp.save_btn.set_label(&gettext("Save"));
        self.set_title(&gettext("Edit Account"));
    }

    pub fn account_data(&self) -> (String, Credential) {
        let imp = self.imp();

        let server = imp
            .server_url
            .get()
            .map(|s| s.as_str())
            .unwrap_or("https://ntfy.sh");

        let credential = if imp.auth_mode_row.selected() == AUTH_MODE_TOKEN {
            Credential::Bearer {
                token: imp.token_entry.text().to_string(),
            }
        } else {
            Credential::Basic {
                username: imp.username_entry.text().to_string(),
                password: imp.password_entry.text().to_string(),
            }
        };

        (server.into(), credential)
    }
}
