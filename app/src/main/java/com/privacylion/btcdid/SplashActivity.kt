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
    
    // Load Dancing Script font
    val dancingScriptTypeface = remember {
        try {
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                context.resources.getFont(R.font.dancing_script)
            } else {
                Typeface.create("cursive", Typeface.NORMAL)
            }
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
        val canvasWidth = size.width
        val canvasHeight = size.height
        
        // Create paint with Dancing Script font
        val textPaint = android.graphics.Paint().apply {
            this.typeface = typeface
            textSize = canvasHeight * 0.9f  // Large S
            isAntiAlias = true
        }
        
        // Extract the path of "S" from the font
        val androidPath = android.graphics.Path()
        textPaint.getTextPath("S", 0, 1, 0f, 0f, androidPath)
        
        // Get bounds to center it
        val bounds = android.graphics.RectF()
        androidPath.computeBounds(bounds, true)
        
        // Transform to center on canvas
        val matrix = android.graphics.Matrix()
        matrix.postTranslate(
            (canvasWidth - bounds.width()) / 2f - bounds.left,
            (canvasHeight - bounds.height()) / 2f - bounds.top + bounds.height()
        )
        androidPath.transform(matrix)
        
        // Convert to Compose Path
        val composePath = androidPath.asComposePath()
        
        // Measure the path
        val pathMeasure = android.graphics.PathMeasure(androidPath, false)
        val pathLength = pathMeasure.length
        
        // Calculate stroke width based on canvas size
        val strokeWidth = canvasWidth * 0.06f
        
        // Draw glow effect (slightly ahead for smooth look)
        drawPath(
            path = composePath,
            color = Color.White.copy(alpha = 0.4f),
            style = Stroke(
                width = strokeWidth * 1.8f,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
                pathEffect = PathEffect.dashPathEffect(
                    intervals = floatArrayOf(pathLength * progress, pathLength),
                    phase = 0f
                )
            )
        )
        
        // Draw main stroke - the "pen" drawing the S
        drawPath(
            path = composePath,
            color = Color.White,
            style = Stroke(
                width = strokeWidth,
                cap = StrokeCap.Round,
                join = StrokeJoin.Round,
                pathEffect = PathEffect.dashPathEffect(
                    intervals = floatArrayOf(pathLength * progress, pathLength),
                    phase = 0f
                )
            )
        )
    }
}
