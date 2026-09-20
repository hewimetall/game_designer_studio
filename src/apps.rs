/// Local desk surfaces. Game and A-Life stay on the remote stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DesignerTab {
    Level,
    Sprites,
    Bestiary,
}

/// System-wide Authentik apps (not stand editors). Own loopback port, `base: "/"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SystemTab {
    Chat,
    S3,
}

impl DesignerTab {
    pub const ALL: [DesignerTab; 3] = [
        DesignerTab::Level,
        DesignerTab::Sprites,
        DesignerTab::Bestiary,
    ];

    #[inline]
    pub fn id(self) -> &'static str {
        match self {
            DesignerTab::Level => "level",
            DesignerTab::Sprites => "sprites",
            DesignerTab::Bestiary => "bestiary",
        }
    }

    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            DesignerTab::Level => "Level",
            DesignerTab::Sprites => "Sprites",
            DesignerTab::Bestiary => "Bestiary",
        }
    }

    #[inline]
    pub fn station_code(self) -> &'static str {
        match self {
            DesignerTab::Level => "LVL",
            DesignerTab::Sprites => "SPR",
            DesignerTab::Bestiary => "BST",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|tab| tab.id() == id)
    }

    /// Path the bundled Solid editor must see so `apiBasePath()` stays `/stand/<slug>/api`.
    pub fn stand_path(self, slug: &str) -> String {
        format!("/stand/{}/{}/", slug, self.id())
    }
}

impl SystemTab {
    pub const ALL: [SystemTab; 2] = [SystemTab::Chat, SystemTab::S3];

    #[inline]
    pub fn id(self) -> &'static str {
        match self {
            SystemTab::Chat => "chat",
            SystemTab::S3 => "s3",
        }
    }

    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            SystemTab::Chat => "Chat",
            SystemTab::S3 => "S3",
        }
    }

    #[inline]
    pub fn station_code(self) -> &'static str {
        match self {
            SystemTab::Chat => "CHT",
            SystemTab::S3 => "S3",
        }
    }

    #[inline]
    pub fn production_origin(self) -> &'static str {
        match self {
            SystemTab::Chat => "https://chat.mcpwork.space",
            SystemTab::S3 => "https://s3.mcpwork.space",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_package_is_level_sprites_bestiary_only() {
        let ids: Vec<_> = DesignerTab::ALL.iter().map(|tab| tab.id()).collect();
        assert_eq!(ids, ["level", "sprites", "bestiary"]);
        assert!(DesignerTab::from_id("game").is_none());
        assert!(DesignerTab::from_id("alife").is_none());
    }

    #[test]
    fn stand_paths_keep_slug_prefix_for_existing_web_api_base() {
        assert_eq!(
            DesignerTab::Level.stand_path("neweditor"),
            "/stand/neweditor/level/"
        );
        assert!(DesignerTab::Sprites
            .stand_path("neweditor")
            .starts_with("/stand/neweditor/"));
    }

    #[test]
    fn system_tabs_are_chat_and_s3_on_dedicated_hosts() {
        let ids: Vec<_> = SystemTab::ALL.iter().map(|tab| tab.id()).collect();
        assert_eq!(ids, ["chat", "s3"]);
        assert_eq!(
            SystemTab::Chat.production_origin(),
            "https://chat.mcpwork.space"
        );
        assert_eq!(
            SystemTab::S3.production_origin(),
            "https://s3.mcpwork.space"
        );
        assert!(DesignerTab::from_id("chat").is_none());
        assert!(DesignerTab::from_id("s3").is_none());
    }
}
