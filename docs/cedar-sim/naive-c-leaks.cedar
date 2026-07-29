// "authorize(principal, viewUnmasked, resultColumn)" — Cedar gates eligibility,
// but there is NO Cedar expression for "would request.role be allowed here",
// so this policy cannot re-apply pii-reader's `when segregated` condition.
permit(
  principal,
  action == Action::"result.viewUnmasked",
  resource
)
when {
  resource.request.approved &&
  principal == resource.request.requester
};
