package io.github.nevminhnh.mincontrol.master.ui

import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.ui.theme.Contrast
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContrastTest {
    @Test fun everyTextPairMeetsWcagAA() {
        val bad = Contrast.textPairs.map { (fg, bg, name) -> name to Contrast.ratio(fg, bg) }.filter { it.second < 4.5 }
        assertTrue("below 4.5:1: $bad", bad.isEmpty())
    }

    @Test fun nonTextIndicatorsMeet3to1() {
        val bad = Contrast.nonTextPairs.map { (fg, bg, name) -> name to Contrast.ratio(fg, bg) }.filter { it.second < 3.0 }
        assertTrue("below 3:1: $bad", bad.isEmpty())
    }

    @Test fun ratioFormula() {
        val black = androidx.compose.ui.graphics.Color(0xFF000000)
        val white = androidx.compose.ui.graphics.Color(0xFFFFFFFF)
        assertEquals(21.0, Contrast.ratio(black, white), 0.01)
        assertEquals(1.0, Contrast.ratio(white, white), 0.001)
    }

    @Test fun switcherLabelsDisambiguateDuplicates() {
        val kids = listOf(
            Child("d1", "PC-A", "S1", "Minh", true, null, null),
            Child("d2", "PC-B", "S2", "Minh", true, null, null),
            Child("d3", "PC-C", "S3", "Lan", true, null, null),
        )
        assertEquals(listOf("Minh · PC-A", "Minh · PC-B", "Lan"), switcherLabels(kids))
    }
}
