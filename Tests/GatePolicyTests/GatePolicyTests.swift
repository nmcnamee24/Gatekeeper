import XCTest
@testable import GatePolicy
final class GatePolicyTests: XCTestCase {
    func testFailClosed() {
        for a in [false, true] { for b in [false, true] { for c in [false, true] {
            XCTAssertEqual(GatePolicy.approves(approved: a, concretePurpose: b, exitPlan: c), a && b && c)
        } } }
    }
    func testExpiryBoundaryAndMissingGrant() {
        let now = Date(timeIntervalSince1970: 10000)
        XCTAssertFalse(GatePolicy.isOpen(now: now, expiry: nil))
        XCTAssertFalse(GatePolicy.isOpen(now: now, expiry: now))
        XCTAssertTrue(GatePolicy.isOpen(now: now, expiry: now.addingTimeInterval(1)))
    }
    func testNoImmediateRepeatOrClockRollback() {
        let grant = Date(timeIntervalSince1970: 10000)
        XCTAssertTrue(GatePolicy.eligible(now: grant, lastGrant: nil))
        XCTAssertFalse(GatePolicy.eligible(now: grant, lastGrant: grant))
        XCTAssertFalse(GatePolicy.eligible(now: grant.addingTimeInterval(-1), lastGrant: grant))
        XCTAssertFalse(GatePolicy.eligible(now: grant.addingTimeInterval(2759), lastGrant: grant))
        XCTAssertTrue(GatePolicy.eligible(now: grant.addingTimeInterval(2760), lastGrant: grant))
    }
}
