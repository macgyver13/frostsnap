use crate::{
    address_display::{pick_highlights, AddressDisplay},
    any_of::AnyOf,
    bitcoin_amount_display::BitcoinAmountDisplay,
    gray4_style::Gray4TextStyle,
    page_slider::PageSlider,
    palette::PALETTE,
    prelude::*,
    widget_list::{WidgetList, WidgetListItem},
    GrayToAlpha, HoldToConfirm, Image,
};
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use embedded_graphics::{
    geometry::Size,
    pixelcolor::{Gray8, Rgb565},
};
use frostsnap_core::bitcoin_transaction::PromptSignBitcoinTx;
use frostsnap_fonts::{
    Gray4Font, NOTO_SANS_17_REGULAR, NOTO_SANS_18_LIGHT, NOTO_SANS_18_MEDIUM, NOTO_SANS_24_BOLD,
    NOTO_SANS_MONO_15_REGULAR,
};
use tinybmp::Bmp;

const FONT_PAGE_HEADER: &Gray4Font = &NOTO_SANS_18_LIGHT;
const FONT_CONFIRM_TITLE: &Gray4Font = &NOTO_SANS_18_MEDIUM;
const FONT_CONFIRM_TEXT: &Gray4Font = &NOTO_SANS_17_REGULAR;
const FONT_CAUTION_NOTE: &Gray4Font = &NOTO_SANS_18_MEDIUM;
const FONT_CAUTION_TITLE: &Gray4Font = &NOTO_SANS_24_BOLD;
const FONT_CAUTION_TEXT: &Gray4Font = &NOTO_SANS_17_REGULAR;
const FONT_SILENT_PAYMENT_ADDRESS: &Gray4Font = &NOTO_SANS_MONO_15_REGULAR;
const SP_ADDRESS_HORIZONTAL_SPACING: u32 = 15;

const HIGH_FEE_ABSOLUTE_THRESHOLD_SATS: u64 = 100_000;
const HIGH_FEE_PERCENTAGE_THRESHOLD: u64 = 5;
const HOLD_TO_SIGN_TIME_MS: u32 = 3000;

/// Widget list that generates sign prompt pages
#[derive(Clone)]
pub struct SignPromptPageList {
    prompt: PromptSignBitcoinTx,
    total_pages: usize,
    rand_seed: u32,
}

/// Page widget for displaying amount to send
#[derive(frostsnap_macros::Widget)]
pub struct AmountPage {
    #[widget_delegate]
    center: Center<
        Column<(
            Text<Gray4TextStyle>,
            BitcoinAmountDisplay,
            Text<Gray4TextStyle>,
        )>,
    >,
}

impl AmountPage {
    #[inline(never)]
    pub fn new(index: usize, amount_sats: u64) -> Self {
        let title = Text::new(
            format!("Send Amount #{}", index + 1),
            Gray4TextStyle::new(FONT_PAGE_HEADER, PALETTE.text_secondary),
        );

        let amount_display = BitcoinAmountDisplay::new(amount_sats);

        let btc_text = Text::new(
            "BTC".to_string(),
            Gray4TextStyle::new(FONT_PAGE_HEADER, PALETTE.text_secondary),
        );

        let mut column = Column::new((title, amount_display, btc_text))
            .with_main_axis_alignment(MainAxisAlignment::Center)
            .with_cross_axis_alignment(CrossAxisAlignment::Center);
        column.set_uniform_gap(10);

        Self {
            center: Center::new(column),
        }
    }
}

/// Page widget for displaying recipient address
#[derive(Clone, frostsnap_macros::Widget)]
pub struct AddressPage {
    #[widget_delegate]
    center: Center<Padding<Column<(Text<Gray4TextStyle>, AddressDisplay)>>>,
}

impl AddressPage {
    #[inline(never)]
    pub fn new_with_seed(index: usize, address: &bitcoin::Address, rand_seed: u32) -> Self {
        let title = Text::new(
            format!("To Address #{}", index + 1),
            Gray4TextStyle::new(FONT_PAGE_HEADER, PALETTE.text_secondary),
        );

        let mixed_seed = rand_seed.wrapping_add((index as u32).wrapping_mul(0x9e3779b9));
        let address_display = AddressDisplay::new_with_seed(address.clone(), mixed_seed);

        let mut column = Column::new((title, address_display))
            .with_main_axis_alignment(MainAxisAlignment::Start);
        column.set_gap(0, 10);
        let padded = Padding::only(column).bottom(40).build();

        Self {
            center: Center::new(padded),
        }
    }
}

fn chunk_silent_payment_address(address: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut pos = 0;
    while pos < address.len() {
        let end = (pos + 4).min(address.len());
        chunks.push(format!("{:4}", &address[pos..end]));
        pos = end;
    }
    chunks
}

/// In the address's monospace font, the one where every contact name fits on a line.
fn contact_title(title: String) -> Text<Gray4TextStyle> {
    Text::new(
        title,
        Gray4TextStyle::new(FONT_SILENT_PAYMENT_ADDRESS, PALETTE.on_background),
    )
}

type SilentPaymentAddressDisplay = Column<Vec<Row<Vec<Text<Gray4TextStyle>>>>>;

/// A silent payment contact's address, in groups of four with a few highlighted, like
/// [`AddressPage`]. A silent payment address is too long for `AddressDisplay`'s layout, so it
/// gets a smaller monospace font. `title` says what the address is to the user.
#[derive(Clone, frostsnap_macros::Widget)]
pub struct SilentPaymentAddressPage {
    #[widget_delegate]
    center: Center<Padding<Column<(Text<Gray4TextStyle>, SilentPaymentAddressDisplay)>>>,
}

impl SilentPaymentAddressPage {
    #[inline(never)]
    pub fn new_with_seed(index: usize, title: String, address: &str, rand_seed: u32) -> Self {
        let title = contact_title(title);

        let chunks = chunk_silent_payment_address(address);
        let mixed_seed = rand_seed.wrapping_add((index as u32).wrapping_mul(0x9e3779b9));
        let highlighted = pick_highlights(mixed_seed, chunks.len());

        let mut rows = Vec::new();
        for (row_idx, chunk_slice) in chunks.chunks(3).enumerate() {
            let mut row_texts = Vec::new();
            for (col_idx, chunk_str) in chunk_slice.iter().enumerate() {
                let color = if highlighted.contains(&(row_idx * 3 + col_idx)) {
                    PALETTE.on_background
                } else {
                    PALETTE.primary
                };
                row_texts.push(Text::new(
                    chunk_str.clone(),
                    Gray4TextStyle::new(FONT_SILENT_PAYMENT_ADDRESS, color),
                ));
            }
            let mut row = Row::new(row_texts).with_main_axis_alignment(MainAxisAlignment::Center);
            row.set_uniform_gap(SP_ADDRESS_HORIZONTAL_SPACING);
            rows.push(row);
        }
        let mut address_col = Column::new(rows);
        address_col.set_uniform_gap(1);

        let mut column = Column::new((title, address_col))
            .with_main_axis_alignment(MainAxisAlignment::Start)
            .with_cross_axis_alignment(CrossAxisAlignment::Center);
        column.set_gap(0, 10);
        let padded = Padding::only(column).bottom(30).build();

        Self {
            center: Center::new(padded),
        }
    }
}

/// Page widget for displaying network fee
#[derive(frostsnap_macros::Widget)]
pub struct FeePage {
    #[widget_delegate]
    center: Center<
        Column<(
            Text<Gray4TextStyle>,
            BitcoinAmountDisplay,
            Text<Gray4TextStyle>,
        )>,
    >,
}

impl FeePage {
    #[inline(never)]
    fn new(fee_sats: u64, fee_rate_sats_per_vbyte: Option<f64>) -> Self {
        let title = Text::new(
            "Network Fee".to_string(),
            Gray4TextStyle::new(FONT_PAGE_HEADER, PALETTE.text_secondary),
        );

        let fee_amount = BitcoinAmountDisplay::new(fee_sats);

        let fee_rate_text = if let Some(rate) = fee_rate_sats_per_vbyte {
            Text::new(
                format!("{:.1} sats/vB", rate),
                Gray4TextStyle::new(FONT_PAGE_HEADER, PALETTE.text_secondary),
            )
        } else {
            Text::new(
                "BTC".to_string(),
                Gray4TextStyle::new(FONT_PAGE_HEADER, PALETTE.text_secondary),
            )
        };

        let mut column = Column::new((title, fee_amount, fee_rate_text))
            .with_main_axis_alignment(MainAxisAlignment::Center)
            .with_cross_axis_alignment(CrossAxisAlignment::Center);
        column.set_uniform_gap(10);

        Self {
            center: Center::new(column),
        }
    }
}

const WARNING_ICON_DATA: &[u8] = include_bytes!("../assets/warning-icon-24x24.bmp");

/// Page widget for high fee warning
#[derive(frostsnap_macros::Widget)]
pub struct WarningPage {
    #[widget_delegate]
    center: Center<
        Column<(
            Row<(
                Image<GrayToAlpha<Bmp<'static, Gray8>, Rgb565>>,
                SizedBox<Rgb565>,
                Column<(SizedBox<Rgb565>, Text<Gray4TextStyle>)>,
            )>,
            Text<Gray4TextStyle>,
            Column<(Text<Gray4TextStyle>, Text<Gray4TextStyle>)>,
        )>,
    >,
}

impl WarningPage {
    #[inline(never)]
    fn new(fee_sats: u64, _total_sent: u64) -> Self {
        let warning_bmp =
            Bmp::<Gray8>::from_slice(WARNING_ICON_DATA).expect("Failed to load warning icon BMP");
        let warning_icon = Image::new(GrayToAlpha::new(warning_bmp, PALETTE.warning));

        let icon_spacer = SizedBox::<Rgb565>::new(Size::new(5, 1));

        let caution_text = Text::new(
            "Caution".to_string(),
            Gray4TextStyle::new(FONT_CAUTION_NOTE, PALETTE.warning),
        );

        let text_with_spacer =
            Column::new((SizedBox::<Rgb565>::new(Size::new(1, 5)), caution_text));

        let caution_row = Row::new((warning_icon, icon_spacer, text_with_spacer))
            .with_main_axis_alignment(MainAxisAlignment::Center);

        let title_text = Text::new(
            "High Fee".to_string(),
            Gray4TextStyle::new(FONT_CAUTION_TITLE, PALETTE.on_background),
        );

        let (line1, line2) = if fee_sats > HIGH_FEE_ABSOLUTE_THRESHOLD_SATS {
            ("Fee is greater".to_string(), "than 0.001 BTC".to_string())
        } else {
            (
                "Fee exceeds 5% of the".to_string(),
                "amount being sent".to_string(),
            )
        };

        let warning_text = Column::new((
            Text::new(
                line1,
                Gray4TextStyle::new(FONT_CAUTION_TEXT, PALETTE.text_secondary),
            ),
            Text::new(
                line2,
                Gray4TextStyle::new(FONT_CAUTION_TEXT, PALETTE.text_secondary),
            ),
        ))
        .with_cross_axis_alignment(CrossAxisAlignment::Center);

        let mut column = Column::new((caution_row, title_text, warning_text))
            .with_main_axis_alignment(MainAxisAlignment::Center)
            .with_cross_axis_alignment(CrossAxisAlignment::Center);
        column.set_uniform_gap(10);

        Self {
            center: Center::new(column),
        }
    }
}

/// Confirmation page with HoldToConfirm
#[derive(frostsnap_macros::Widget)]
pub struct ConfirmationPage {
    #[widget_delegate]
    pub hold_confirm: HoldToConfirm<
        Column<(
            Text<Gray4TextStyle>,
            Column<(Text<Gray4TextStyle>, Text<Gray4TextStyle>)>,
        )>,
    >,
}

impl ConfirmationPage {
    #[inline(never)]
    fn new() -> Self {
        Self::with_text("Hold to Sign", "Press and hold", "for 3 seconds")
    }

    #[inline(never)]
    fn with_text(title: &str, line1: &str, line2: &str) -> Self {
        let sign_text = Text::new(
            title.to_string(),
            Gray4TextStyle::new(FONT_CONFIRM_TITLE, PALETTE.on_background),
        );

        let press_text = Column::new((
            Text::new(
                line1.to_string(),
                Gray4TextStyle::new(FONT_CONFIRM_TEXT, PALETTE.text_secondary),
            ),
            Text::new(
                line2.to_string(),
                Gray4TextStyle::new(FONT_CONFIRM_TEXT, PALETTE.text_secondary),
            ),
        ));

        let mut confirm_content = Column::new((sign_text, press_text))
            .with_main_axis_alignment(MainAxisAlignment::Center)
            .with_cross_axis_alignment(CrossAxisAlignment::Center);
        confirm_content.set_gap(0, 15);

        let hold_confirm =
            HoldToConfirm::new(HOLD_TO_SIGN_TIME_MS, confirm_content).with_faded_out_button();

        Self { hold_confirm }
    }

    pub fn is_confirmed(&self) -> bool {
        self.hold_confirm.is_confirmed()
    }

    pub fn is_finished(&self) -> bool {
        self.hold_confirm.is_finished()
    }
}

type SignPromptPage = AnyOf<(
    AmountPage,
    AddressPage,
    SilentPaymentAddressPage,
    FeePage,
    WarningPage,
    ConfirmationPage,
)>;

impl SignPromptPageList {
    fn new_with_seed(prompt: PromptSignBitcoinTx, rand_seed: u32) -> Self {
        let num_recipients = prompt.foreign_recipients.len();
        let has_warning = Self::has_high_fee(&prompt);

        let total_pages = num_recipients * 2 + 1 + if has_warning { 1 } else { 0 } + 1;

        Self {
            prompt,
            total_pages,
            rand_seed,
        }
    }

    fn has_high_fee(prompt: &PromptSignBitcoinTx) -> bool {
        let fee_sats = prompt.fee.to_sat();

        if fee_sats > HIGH_FEE_ABSOLUTE_THRESHOLD_SATS {
            return true;
        }

        let total_sent: u64 = prompt
            .foreign_recipients
            .iter()
            .map(|(_, amount)| amount.to_sat())
            .sum();
        if total_sent > 0 && fee_sats > total_sent * HIGH_FEE_PERCENTAGE_THRESHOLD / 100 {
            return true;
        }

        false
    }
}

impl WidgetList for SignPromptPageList {
    type Widget = SignPromptPage;

    fn len(&self) -> usize {
        self.total_pages
    }

    fn get(&self, index: usize) -> Option<WidgetListItem<SignPromptPage>> {
        if index >= self.total_pages {
            return None;
        }

        let num_recipients = self.prompt.foreign_recipients.len();
        let recipient_pages = num_recipients * 2;
        let has_warning = Self::has_high_fee(&self.prompt);

        let (page, use_fb) = if index < recipient_pages {
            let recipient_idx = index / 2;
            let is_amount = index.is_multiple_of(2);

            if is_amount {
                let (_, amount) = &self.prompt.foreign_recipients[recipient_idx];
                (
                    SignPromptPage::new(AmountPage::new(recipient_idx, amount.to_sat())),
                    false,
                )
            } else {
                let (address, _) = &self.prompt.foreign_recipients[recipient_idx];
                (
                    SignPromptPage::new(AddressPage::new_with_seed(
                        recipient_idx,
                        address,
                        self.rand_seed,
                    )),
                    true,
                )
            }
        } else if has_warning && index == recipient_pages {
            let total_sent: u64 = self
                .prompt
                .foreign_recipients
                .iter()
                .map(|(_, amount)| amount.to_sat())
                .sum();
            (
                SignPromptPage::new(WarningPage::new(self.prompt.fee.to_sat(), total_sent)),
                false,
            )
        } else if (has_warning && index == recipient_pages + 1)
            || (!has_warning && index == recipient_pages)
        {
            (
                SignPromptPage::new(FeePage::new(
                    self.prompt.fee.to_sat(),
                    self.prompt.fee_rate_sats_per_vbyte,
                )),
                false,
            )
        } else {
            (SignPromptPage::new(ConfirmationPage::new()), false)
        };

        let mut item = WidgetListItem::new(page);
        if use_fb {
            item = item.with_framebuffer_transitions(true);
        }
        Some(item)
    }

    fn can_go_prev(&self, from_index: usize, current_widget: &SignPromptPage) -> bool {
        if from_index == 0 {
            return false;
        }
        if from_index == self.total_pages - 1 {
            if let Some(confirmation_page) = current_widget.downcast_ref::<ConfirmationPage>() {
                return !confirmation_page.is_confirmed();
            }
        }
        true
    }
}

/// High-level widget that manages the complete sign prompt flow using PageSlider
#[derive(frostsnap_macros::Widget)]
pub struct SignTxPrompt {
    #[widget_delegate]
    page_slider: Box<PageSlider<SignPromptPageList>>,
}

impl SignTxPrompt {
    pub fn new(prompt: PromptSignBitcoinTx) -> Self {
        Self::new_with_seed(prompt, 0)
    }

    pub fn new_with_seed(prompt: PromptSignBitcoinTx, rand_seed: u32) -> Self {
        let page_list = SignPromptPageList::new_with_seed(prompt, rand_seed);
        let mut page_slider = Box::new(PageSlider::new(page_list));
        page_slider.set_on_page_ready(|page| {
            if let Some(confirmation_page) = page.downcast_mut::<ConfirmationPage>() {
                confirmation_page.hold_confirm.fade_in_button();
            }
        });
        page_slider.enable_swipe_up_chevron();

        Self { page_slider }
    }

    pub fn is_confirmed(&mut self) -> bool {
        if self.page_slider.current_index() == self.page_slider.total_pages() - 1 {
            let current_widget = self.page_slider.current_widget();
            if let Some(confirmation_page) = current_widget.downcast_ref::<ConfirmationPage>() {
                return confirmation_page.is_confirmed();
            }
        }
        false
    }

    pub fn is_finished(&mut self) -> bool {
        if self.page_slider.current_index() == self.page_slider.total_pages() - 1 {
            let current_widget = self.page_slider.current_widget();
            if let Some(confirmation_page) = current_widget.downcast_ref::<ConfirmationPage>() {
                return confirmation_page.is_finished();
            }
        }
        false
    }
}

/// The pages of adding a contact: its name and address, then the hold.
pub struct SpContactPageList {
    name: String,
    address: String,
    rand_seed: u32,
}

impl WidgetList for SpContactPageList {
    type Widget = SignPromptPage;

    fn len(&self) -> usize {
        2
    }

    fn get(&self, index: usize) -> Option<WidgetListItem<SignPromptPage>> {
        match index {
            0 => Some(
                WidgetListItem::new(SignPromptPage::new(
                    SilentPaymentAddressPage::new_with_seed(
                        0,
                        format!("Add {}", self.name),
                        &self.address,
                        self.rand_seed,
                    ),
                ))
                .with_framebuffer_transitions(true),
            ),
            1 => Some(WidgetListItem::new(SignPromptPage::new(
                ConfirmationPage::with_text(
                    "Hold to Trust",
                    "Is the address right?",
                    "Press and hold",
                ),
            ))),
            _ => None,
        }
    }

    fn can_go_prev(&self, from_index: usize, current_widget: &SignPromptPage) -> bool {
        from_index == 1
            && !current_widget
                .downcast_ref::<ConfirmationPage>()
                .is_some_and(ConfirmationPage::is_confirmed)
    }
}

/// The prompt to add a trusted contact. This is where the user checks the address: a send to the
/// contact relies on this check.
#[derive(frostsnap_macros::Widget)]
pub struct SpContactPrompt {
    #[widget_delegate]
    page_slider: Box<PageSlider<SpContactPageList>>,
}

impl SpContactPrompt {
    pub fn new(name: String, address: String, rand_seed: u32) -> Self {
        let mut page_slider = Box::new(PageSlider::new(SpContactPageList {
            name,
            address,
            rand_seed,
        }));
        page_slider.set_on_page_ready(|page| {
            if let Some(confirmation_page) = page.downcast_mut::<ConfirmationPage>() {
                confirmation_page.hold_confirm.fade_in_button();
            }
        });
        page_slider.enable_swipe_up_chevron();
        Self { page_slider }
    }

    pub fn is_confirmed(&mut self) -> bool {
        self.confirmation_page()
            .is_some_and(ConfirmationPage::is_confirmed)
    }

    pub fn is_finished(&mut self) -> bool {
        self.confirmation_page()
            .is_some_and(ConfirmationPage::is_finished)
    }

    fn confirmation_page(&mut self) -> Option<&ConfirmationPage> {
        self.page_slider
            .current_widget()
            .downcast_ref::<ConfirmationPage>()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// A title that ran off the screen would hide part of a name the user is trusting. `Text` does
    /// not wrap, so the longest name must fit on its own.
    #[test]
    fn the_longest_contact_name_fits_on_the_address_page() {
        use frostsnap_core::silent_payments::MAX_CONTACT_NAME_LEN;
        for prefix in ["To", "Add"] {
            let name = "W".repeat(MAX_CONTACT_NAME_LEN);
            let title = contact_title(format!("{prefix} {name}"));
            assert!(title.sizing().width <= 240);
        }
    }
}
