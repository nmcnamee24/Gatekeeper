import Foundation
@main struct VerifyPolicy {
static func main() {
let now = Date(timeIntervalSince1970: 10000)
var checks = 0
func check(_ value: Bool) { precondition(value); checks += 1 }
for a in [false, true] { for b in [false, true] { for c in [false, true] {
    check(GatePolicy.approves(approved: a, concretePurpose: b, exitPlan: c) == (a && b && c))
}}}
check(!GatePolicy.isOpen(now: now, expiry: nil))
check(!GatePolicy.isOpen(now: now, expiry: now))
check(GatePolicy.isOpen(now: now, expiry: now.addingTimeInterval(1)))
check(GatePolicy.eligible(now: now, lastGrant: nil))
check(!GatePolicy.eligible(now: now, lastGrant: now))
check(!GatePolicy.eligible(now: now.addingTimeInterval(-1), lastGrant: now))
check(!GatePolicy.eligible(now: now.addingTimeInterval(2759), lastGrant: now))
check(GatePolicy.eligible(now: now.addingTimeInterval(2760), lastGrant: now))
print("Passed \(checks) policy checks")

}
}
