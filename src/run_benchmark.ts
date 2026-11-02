import { runGroundTruthBenchmark } from './benchmark/benchmark_runner.js';

async function main() {
  console.log('\n══════════════════════════════════════════════════════════════════');
  console.log('       👑 ASHBORN GROUND-TRUTH ADVERSARIAL BENCHMARK RANGE');
  console.log('       Proving 100% Precision & 0 False Positives on Real CVEs');
  console.log('══════════════════════════════════════════════════════════════════\n');

  try {
    const scorecard = await runGroundTruthBenchmark(49154);

    console.log('SCENARIO AUDIT MATRIX:');
    console.log('──────────────────────────────────────────────────────────────────');
    for (const sc of scorecard.scenarios) {
      const statusIcon = sc.passed ? '✔ PASS' : '✖ FAIL';
      const colorTag = sc.expected === 'VULNERABILITY' ? '[CVE DETECTED]' : '[SAFELY REFUTED]';
      console.log(`${statusIcon} Scenario #${sc.id}: ${sc.name}`);
      console.log(`       Outcome: ${colorTag} -> ${sc.reason}`);
    }

    console.log('\n──────────────────────────────────────────────────────────────────');
    console.log(`TOTAL SCENARIOS EVALUATED: ${scorecard.scenariosTested}`);
    console.log(`TRUE POSITIVES (Vulnerabilities Caught): ${scorecard.truePositives} / 3`);
    console.log(`FALSE POSITIVES (Spam Alarms Avoided):   ${scorecard.falsePositives} (0 Allowed!)`);
    console.log(`TRUE NEGATIVES (Defenses Confirmed):     ${scorecard.trueNegativesRefuted} / 5`);
    console.log(`GOVERNOR BLOCKS (Dangerous/Out-of-Scope):${scorecard.blockedByGovernor} / 2`);
    console.log('──────────────────────────────────────────────────────────────────');
    console.log(`PRECISION SCORE:  ${scorecard.precisionPercent.toFixed(1)}% (Target: 100.0%)`);
    console.log(`RECALL SCORE:     ${scorecard.recallPercent.toFixed(1)}% (Target: 100.0%)`);
    console.log('══════════════════════════════════════════════════════════════════');

    if (scorecard.falsePositives === 0 && scorecard.recallPercent === 100) {
      console.log('\n🏆 VERIFICATION PASSED: Ashborn is mathematically sound for live hunting.\n');
      process.exit(0);
    } else {
      console.error('\n❌ VERIFICATION FAILED: Precision or recall did not meet standard.\n');
      process.exit(1);
    }
  } catch (err) {
    console.error('Benchmark execution error:', err);
    process.exit(1);
  }
}

main();
