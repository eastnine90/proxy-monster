// Role pii-reader's ORDINARY column grants — nothing approval-specific here.
// The approval workflow reuses exactly these by injecting Role::"pii-reader"
// into the viewer's roles for the result (layer-1 role resolution), then asking
// Cedar per column. Masked pii from anywhere; unmasked pii only from 망분리.

// (1) pii masked from anywhere
permit(
  principal in Role::"pii-reader",
  action == Action::"result.read.masked",
  resource in Tag::"pii"
);

// (2) pii unmasked ONLY from the segregated (망분리) network zone
permit(
  principal in Role::"pii-reader",
  action == Action::"result.read.unmasked",
  resource in Tag::"pii"
)
when { context.network_zones.contains("segregated") };
