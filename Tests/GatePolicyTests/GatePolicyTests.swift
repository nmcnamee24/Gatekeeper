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
    func testCooldownUsesApprovedEndAndSurvivesEarlyClose() {
        let grant = Date(timeIntervalSince1970: 10000)
        let end = grant.addingTimeInterval(5 * 60)
        XCTAssertFalse(GatePolicy.eligible(now: end.addingTimeInterval(1799), lastGrant: grant, lastWindowEnd: end))
        XCTAssertTrue(GatePolicy.eligible(now: end.addingTimeInterval(1800), lastGrant: grant, lastWindowEnd: end))
        XCTAssertFalse(GatePolicy.eligible(now: grant.addingTimeInterval(-1), lastGrant: grant, lastWindowEnd: end))
    }
    func testShortWindowsMonitorAnOngoingIntervalEndingAtApprovedExpiry() throws {
        let now = Date(timeIntervalSince1970: 10000.25)
        for minutes in [1, 5, 15] {
            let requested = now.addingTimeInterval(Double(minutes * 60))
            let plan = try XCTUnwrap(GatePolicy.relockSchedule(now: now, requestedEnd: requested))
            XCTAssertEqual(plan.intervalEnd, plan.expiry)
            XCTAssertGreaterThan(plan.intervalEnd.timeIntervalSince(plan.intervalStart), 15 * 60)
            XCTAssertLessThan(plan.intervalStart, now)
            XCTAssertLessThanOrEqual(plan.expiry, requested)
        }
        XCTAssertNil(GatePolicy.relockSchedule(now: now, requestedEnd: now))
        XCTAssertNil(GatePolicy.relockSchedule(now: now, requestedEnd: now.addingTimeInterval(0.5)))
        XCTAssertNil(GatePolicy.relockSchedule(now: now, requestedEnd: now.addingTimeInterval(901)))
        // A nearly expired response never receives a fresh full window.
        let delayed = try XCTUnwrap(GatePolicy.relockSchedule(now: now, requestedEnd: now.addingTimeInterval(2)))
        XCTAssertLessThanOrEqual(delayed.expiry.timeIntervalSince(now), 2)
    }
}
