use super::{FONT_CONFIRM_TEXT, FONT_PAGE_HEADER};
use crate::{
    bitcoin_amount_display::BitcoinAmountDisplay, gray4_style::Gray4TextStyle, palette::PALETTE,
    prelude::*,
};
use alloc::{format, string::ToString};

/// Summary page for transactions with many recipients
#[derive(frostsnap_macros::Widget)]
pub struct SummaryPage {
    #[widget_delegate]
    center: Center<
        Column<(
            Text<Gray4TextStyle>,
            BitcoinAmountDisplay,
            Text<Gray4TextStyle>,
            Text<Gray4TextStyle>,
        )>,
    >,
}

impl SummaryPage {
    #[inline(never)]
    pub fn new(
        num_recipients: usize,
        total_sent_sats: u64,
        fee_sats: u64,
        fee_rate: Option<f64>,
    ) -> Self {
        let recipients_text = Text::new(
            if num_recipients == 1 {
                "1 recipient".to_string()
            } else {
                format!("{} recipients", num_recipients)
            },
            Gray4TextStyle::new(FONT_PAGE_HEADER, PALETTE.text_secondary),
        );

        let amount_display = BitcoinAmountDisplay::new(total_sent_sats);

        let btc_text = Text::new(
            "BTC".to_string(),
            Gray4TextStyle::new(FONT_PAGE_HEADER, PALETTE.text_secondary),
        );

        let fee_str = if let Some(rate) = fee_rate {
            format!("Fee: {} sats ({:.1} sats/vB)", fee_sats, rate)
        } else {
            format!("Fee: {} sats", fee_sats)
        };
        let fee_text = Text::new(
            fee_str,
            Gray4TextStyle::new(FONT_CONFIRM_TEXT, PALETTE.text_secondary),
        );

        let mut column = Column::new((recipients_text, amount_display, btc_text, fee_text))
            .with_main_axis_alignment(MainAxisAlignment::Center)
            .with_cross_axis_alignment(CrossAxisAlignment::Center);
        column.set_gap(0, 4);
        column.set_gap(1, 2);
        column.set_gap(2, 8);

        Self {
            center: Center::new(column),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics::geometry::Size;

    #[test]
    fn summary_fits_the_device_screen() {
        let mut page = SummaryPage::new(4, 1_000_000, 500, Some(1.0));
        page.set_constraints(Size::new(240, 280));
        let content = page.sizing().dirty_rect();
        let bottom_right = content.bottom_right().unwrap();
        assert!(bottom_right.x < 240 && bottom_right.y < 280, "{content:?}");
    }
}
