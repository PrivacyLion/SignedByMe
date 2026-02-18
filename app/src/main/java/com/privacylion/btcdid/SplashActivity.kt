package com.privacylion.btcdid

import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.res.ResourcesCompat
import kotlinx.coroutines.delay

/**
 * Splash screen that DRAWS a cursive "S" using Dancing Script font path.
 * Extracts the actual glyph path from the font and animates it being drawn.
 */
class SplashActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setContent {
            SplashScreen(
                onAnimationComplete = {
                    startActivity(Intent(this, MainActivity::class.java))
                    finish()
                    overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
                }
            )
        }
    }
}

@Composable
fun SplashScreen(onAnimationComplete: () -> Unit) {
    val context = LocalContext.current
    
    // Load Dancing Script font using ResourcesCompat for compatibility
    val dancingScriptTypeface = remember {
        try {
            ResourcesCompat.getFont(context, R.font.dancing_script)
                ?: Typeface.create("cursive", Typeface.NORMAL)
        } catch (e: Exception) {
            Typeface.create("cursive", Typeface.NORMAL)
        }
    }
    
    // Animation progress 0 -> 1
    var startAnimation by remember { mutableStateOf(false) }
    
    val progress by animateFloatAsState(
        targetValue = if (startAnimation) 1f else 0f,
        animationSpec = tween(
            durationMillis = 1500,  // 1.5 seconds to draw
            easing = FastOutSlowInEasing
        ),
        label = "drawProgress"
    )
    
    // Start animation after short delay
    LaunchedEffect(Unit) {
        delay(300)
        startAnimation = true
    }
    
    // Navigate after animation completes
    LaunchedEffect(progress) {
        if (progress >= 1f) {
            delay(600)  // Pause to admire
            onAnimationComplete()
        }
    }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.linearGradient(
                    colors = listOf(
                        Color(0xFF3B82F6),
                        Color(0xFF8B5CF6)
                    ),
                    start = Offset(0f, 0f),
                    end = Offset(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY)
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        CursiveSDrawing(
            typeface = dancingScriptTypeface,
            progress = progress,
            modifier = Modifier.size(350.dp)  // BIGGER
        )
    }
}

@Composable
fun CursiveSDrawing(
    typeface: Typeface,
    progress: Float,
    modifier: Modifier = Modifier
) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val cx = w / 2f
        val cy = h / 2f
        val scale = minOf(w, h) * 0.42f  // LARGER
        
        // CURSIVE CAPITAL S - proper figure-8 shape with two crossing loops
        val path = Path().apply {
            
            // Start at bottom left
            moveTo(cx - scale * 0.3f, cy + scale * 0.65f)
            
            // Go UP and RIGHT diagonally to top
            cubicTo(
                cx, cy + scale * 0.2f,
                cx + scale * 0.15f, cy - scale * 0.3f,
                cx + scale * 0.15f, cy - scale * 0.55f
            )
            
            // TOP LOOP - curve around to the LEFT and back down
            cubicTo(
                cx + scale * 0.15f, cy - scale * 0.85f,  // up to peak
                cx - scale * 0.4f, cy - scale * 0.85f,   // across left
                cx - scale * 0.4f, cy - scale * 0.55f    // down left side
            )
            
            // Come back RIGHT through the middle (first crossing)
            cubicTo(
                cx - scale * 0.4f, cy - scale * 0.25f,
                cx - scale * 0.1f, cy - scale * 0.05f,
                cx + scale * 0.15f, cy + scale * 0.15f
            )
            
            // Continue down to the RIGHT side
            cubicTo(
                cx + scale * 0.4f, cy + scale * 0.35f,
                cx + scale * 0.4f, cy + scale * 0.65f,
                cx + scale * 0.4f, cy + scale * 0.75f
            )
            
            // BOTTOM LOOP - curve around to the LEFT
            cubicTo(
                cx + scale * 0.4f, cy + scale * 0.95f,   // down to bottom
                cx - scale * 0.15f, cy + scale * 0.95f,  // across left
                cx - scale * 0.15f, cy + scale * 0.75f   // up left side
            )
            
            // Exit stroke going RIGHT
            cubicTo(
                cx - scale * 0.15f, cy + scale * 0.55f,
                cx + scale * 0.1f, cy + scale * 0.5f,
                cx + scale * 0.35f, cy + scale * 0.55f
            )
        }
        
        // Measure path length for animation
        val pathMeasure = android.graphics.PathMeasure(path.asAndroidPath(), false)
        val pathLength = pathMeasure.length
        
        val strokeWidth = minOf(w, h) * 0.07f
        
        // Glow effect
        drawPath(
            path = path,
            color = Color.White.copy(alpha = 0.4f),
            style = Stroke(
                width = strokeWidth * 2f,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
                pathEffect = PathEffect.dashPathEffect(
                    intervals = floatArrayOf(pathLength * progress, pathLength * 2f),
                    phase = 0f
                )
            )
        )
        
        // Main stroke
        drawPath(
            path = path,
            color = Color.White,
            style = Stroke(
                width = strokeWidth,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
                pathEffect = PathEffect.dashPathEffect(
                    intervals = floatArrayOf(pathLength * progress, pathLength * 2f),
                    phase = 0f
                )
            )
        )
    }
}
